#!/usr/bin/env python3
"""Oleg Legal: opt-in Yandex offline conversion delivery, qualified non-test CRM only.

Default mode performs no network or write. No Bitrix access or credential harvesting.
Event source must be independently verified CRM records screened by conversion_router.
"""
from __future__ import annotations
import argparse, csv, io, json, os, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path
import requests
from conversion_router import CONFIG, GOALS, route_records, InvalidRecord

EXPECTED = {
    114249897: {'oleg_crm_lead_confirmed': 688078495,
                'oleg_crm_consultation_completed': 688074736,
                'oleg_crm_contract_signed': 688079852},
    114251443: {'oleg_crm_lead_confirmed': 688081208,
                'oleg_crm_consultation_completed': 688082535,
                'oleg_crm_contract_signed': 688083707},
}
BASE = 'https://api-metrika.yandex.net/management/v1/counter'

class Blocked(Exception):
    pass

def input_records(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 150000:
        raise Blocked('INPUT_NOT_ALLOWED')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise Blocked('INPUT_MUST_BE_ARRAY')
    return data

def csv_payload(rows):
    s = io.StringIO(newline='')
    writer = csv.DictWriter(s, ['ClientId', 'Target', 'DateTime'], lineterminator='\n')
    writer.writeheader()
    for r in rows:
        writer.writerow({'ClientId': r.client_id, 'Target': r.target, 'DateTime': r.timestamp})
    return s.getvalue().encode('utf-8')

def api_goals_exact(counter: int, token: str, http):
    result = http.get(f'{BASE}/{counter}/goals',
                      headers={'Authorization': 'OAuth ' + token},
                      timeout=(8, 18), allow_redirects=False)
    if result.status_code != 200:
        raise Blocked('METRIKA_GOALS_ACCESS_DENIED')
    actual = {g.get('id'): g for g in result.json().get('goals', [])
              if isinstance(g, dict) and type(g.get('id')) is int}
    for event, goal_id in EXPECTED[counter].items():
        goal = actual.get(goal_id)
        if not goal or goal.get('type') != 'action' or goal.get('status') == 'deleted':
            raise Blocked('EXPECTED_ACTION_GOAL_NOT_FOUND')
        conditions = goal.get('conditions')
        if (not isinstance(conditions, list) or len(conditions) != 1
            or conditions[0].get('type') != 'exact'
            or conditions[0].get('url') != event):
            raise Blocked('GOAL_CONDITION_NOT_EXACT')
    return True

def guarded_ledger(path: Path):
    if path.is_symlink():
        raise Blocked('LEDGER_SYMLINK')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    old_umask = os.umask(0o077)
    try:
        conn = sqlite3.connect(path, timeout=10)
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    conn.execute('''CREATE TABLE IF NOT EXISTS yandex_uploads (
      counter INTEGER NOT NULL,
      deal_id INTEGER NOT NULL,
      goal TEXT NOT NULL,
      status TEXT NOT NULL,
      upload_id INTEGER,
      at_utc TEXT NOT NULL,
      PRIMARY KEY(counter, deal_id, goal))''')
    conn.commit()
    return conn

def run(input_file: Path, counter: int, ledger_file: Path, *,
        send=False, token=None, http=None, now=None):
    if counter not in EXPECTED:
        raise Blocked('COUNTER_NOT_ALLOWED')
    if now is None:
        now = int(datetime.now(timezone.utc).timestamp())
    routed, rejected = route_records(input_records(input_file), now)
    others = sum(len(items) for c, items in routed.items() if c != counter)
    if others:
        raise Blocked('MIXED_SITES_REJECTED')
    selected = routed[counter]
    if not send:
        return {'mode': 'DRY_RUN_NO_NETWORK', 'counter': counter,
                'eligible': len(selected), 'excluded': rejected, 'uploads': 0}
    if not selected:
        return {'mode': 'NO_QUALIFIED_EVENTS', 'counter': counter, 'uploads': 0}
    token = token or os.getenv('OLEG_METRIKA_OAUTH_TOKEN', '')
    if not token.strip():
        raise Blocked('YANDEX_OAUTH_TOKEN_MISSING')
    http = http or requests.Session()
    # Read goals from the official API before any ledger reservation or POST.
    api_goals_exact(counter, token.strip(), http)
    conn = guarded_ledger(ledger_file)
    stamp = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute('BEGIN IMMEDIATE')
        new = [row for row in selected if not conn.execute(
            'SELECT 1 FROM yandex_uploads WHERE counter=? AND deal_id=? AND goal=?',
            (row.counter, row.deal_id, row.target)).fetchone()]
        if not new:
            conn.rollback()
            return {'mode': 'ALL_ALREADY_RESERVED', 'counter': counter, 'uploads': 0}
        for row in new:
            conn.execute('INSERT INTO yandex_uploads VALUES(?,?,?,?,?,?)',
                         (row.counter, row.deal_id, row.target,
                          'POST_OUTCOME_UNKNOWN', None, stamp))
        conn.commit()  # A lost HTTP response can never cause an automatic duplicate send.
        try:
            resp = http.post(f'{BASE}/{counter}/offline_conversions/upload',
                             headers={'Authorization': 'OAuth ' + token.strip()},
                             params={'type': 'BASIC'},
                             files={'file': ('crm_verified.csv', csv_payload(new), 'text/csv')},
                             timeout=(8, 25), allow_redirects=False)
            if resp.status_code != 200:
                raise Blocked('METRIKA_UPLOAD_RESPONSE_NOT_SUCCESS')
            data = resp.json().get('uploading', {})
            upload_id = data.get('id')
            if type(upload_id) is not int or upload_id <= 0:
                raise Blocked('UPLOAD_ID_NOT_CONFIRMED')
            conn.executemany(
                'UPDATE yandex_uploads SET status=?, upload_id=?, at_utc=? '
                'WHERE counter=? AND deal_id=? AND goal=?',
                [('ACCEPTED_PENDING_METRIKA_PROCESSING', upload_id, stamp,
                  row.counter, row.deal_id, row.target) for row in new])
            conn.commit()
            return {'mode': 'ACCEPTED_PENDING_PROCESSING', 'counter': counter,
                    'submitted': len(new), 'upload_id': upload_id,
                    'excluded': rejected}
        except (requests.RequestException, ValueError, Blocked):
            return {'mode': 'POST_OUTCOME_UNKNOWN_DO_NOT_RETRY',
                    'counter': counter, 'reserved': len(new)}
    finally:
        conn.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--counter', type=int, required=True)
    p.add_argument('--ledger', type=Path, required=True)
    p.add_argument('--send', action='store_true')
    a = p.parse_args()
    result = run(a.input, a.counter, a.ledger, send=a.send)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('mode') != 'POST_OUTCOME_UNKNOWN_DO_NOT_RETRY' else 3

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Blocked, InvalidRecord, OSError, ValueError, requests.RequestException) as e:
        print('UPLOAD_REFUSED_' + type(e).__name__, file=sys.stderr)
        sys.exit(2)
