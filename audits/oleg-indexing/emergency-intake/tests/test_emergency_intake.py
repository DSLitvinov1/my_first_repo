#!/usr/bin/env python3
"""Synthetic-only HTTP integration tests.  Must run on isolated /tmp copy."""
import contextlib
import http.cookiejar
from html.parser import HTMLParser
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[1]
SITE="potrebpravo.ru"

class Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields={}
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=="input" and "name" in a and "value" in a:
            self.fields[a["name"]]=a["value"]

def check(cond,message):
    if not cond: raise AssertionError(message)

def call(opener,port,method="GET",values=None,extra_headers=None,host=SITE,follow=True,query=""):
    u=f"http://127.0.0.1:{port}/emergency-lead.php"+query
    headers={"Host":host}
    if extra_headers: headers.update(extra_headers)
    if values is not None:
        headers.setdefault("Origin","http://"+host)
        headers["Content-Type"]="application/x-www-form-urlencoded"
        method="POST"
        raw=urllib.parse.urlencode(values).encode()
    else: raw=None
    req=urllib.request.Request(u,data=raw,headers=headers,method=method)
    try:
        resp=opener.open(req,timeout=8)
        with resp: return resp.status,resp.url,resp.read().decode("utf8","replace")
    except urllib.error.HTTPError as e:
        return e.code,e.url,e.read().decode("utf8","replace")

def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def form(o,port,host=SITE,query=""):
    code,url,body=call(o,port,host=host,query=query)
    check(code==200 and "Сохранить обращение" in body,"GET form not ready")
    p=Parser();p.feed(body)
    check(len(p.fields.get("csrf",""))==64 and len(p.fields.get("request_id",""))==32,"missing CSRF/id")
    return dict(p.fields)

def valid(f):
    return {**f,"name":"Мария Тест","phone":"+79990000001","problem":"Искусственная заявка для проверки резервной формы, не реальный клиент","consent":"yes","website":""}

def count(conn):
    return conn.execute("SELECT count(*) FROM requests").fetchone()[0]

def main():
    mods=subprocess.check_output(["php","-m"],text=True).lower()
    check("pdo_sqlite" in mods and "sodium" in mods,"PHP sqlite and sodium required")
    with tempfile.TemporaryDirectory(prefix="oleg-v18-intake-test.") as tmp:
        home=pathlib.Path(tmp)
        private=home/".oleg-emergency-intake-v17"
        private.mkdir(mode=0o700)
        for p in (ROOT/"private").glob("*.php"):
            (private/p.name).write_bytes(p.read_bytes())
        public=home/SITE/"public_html"
        public.mkdir(parents=True)
        (public/"emergency-lead.php").write_bytes((ROOT/"public"/"emergency-lead.php").read_bytes())
        install=subprocess.run(["php",str(private/"console.php"),"install",str(private)],capture_output=True,text=True)
        check(install.returncode==0, "Installation failed: "+install.stderr[:250])
        check((private/"intake.sqlite").exists(),"DB not created")
        check((private/"secretbox.key").stat().st_mode & 0o777==0o600,"key mode must be 0600")
        check((private/"intake.sqlite").stat().st_mode & 0o777==0o600,"DB mode must be 0600")
        with socket.socket() as sk:
            sk.bind(("127.0.0.1",0));port=sk.getsockname()[1]
        env={**os.environ,"OLEG_INTAKE_TEST_MODE":"1"}
        server=subprocess.Popen(["php","-S",f"127.0.0.1:{port}","-t",str(public)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            ready=False
            for _ in range(30):
                try:
                    code,_,body=call(opener(),port)
                    if code==200:ready=True;break
                except Exception:time.sleep(0.1)
            check(ready,"PHP server failed to start")
            db=sqlite3.connect(private/"intake.sqlite")
            db.row_factory=sqlite3.Row
            p=opener()
            fields=form(p,port,query="?entry=homepage&utm_source=yandex&utm_medium=cpc&utm_campaign=legal_ad")
            # Unrelated source without cookies cannot post
            status,_,body=call(p,port,values=valid(fields),extra_headers={"Origin":"https://evil.example"})
            check(status==403 and "не сохранено" in body.lower(),"cross-origin not denied")
            check(count(db)==0,"unexpected write from bad origin")
            bad=valid(fields);bad["csrf"]="tampered"
            status,_,body=call(p,port,values=bad)
            check(status==403 and "не сохранено" in body.lower(),"CSRF not denied")
            check(count(db)==0,"unexpected write from bad CSRF")
            bad=valid(fields);bad["consent"]=""
            status,_,body=call(p,port,values=bad)
            check(status==422 and "сохранить обращение" in body.lower(),"missing consent not denied")
            check(count(db)==0,"unexpected write from missing consent")
            no_origin={**valid(fields),"consent":""}
            st,_,out=call(p,port,values=no_origin,extra_headers={"Origin":""})
            check(st==422,"valid same-session CSRF should work when browser omits Origin")
            bad=valid(fields);bad["website"]="bot-value"
            status,_,body=call(p,port,values=bad)
            check(status==422,"honeypot not denied")
            good=valid(fields)
            status,final,body=call(p,port,values=good)
            if not (status==200 and "?receipt=" in final and "сохранено на сервере" in body.lower()):
                m=re.search(r"<title>(.*?)</title>",body)
                print("SUBMIT_DIAGNOSTIC",status,final,("TITLE="+m.group(1) if m else "NO_TITLE"),"ROWS="+str(count(db)))
            check(status==200 and "?receipt=" in final and "сохранено на сервере" in body.lower(),"submit not persisted/acknowledged")
            receipt=urllib.parse.parse_qs(urllib.parse.urlsplit(final).query)["receipt"][0]
            check(count(db)==1,"expected exactly one stored request")
            row=db.execute("SELECT * FROM requests").fetchone()
            check(len(row["ciphertext"])>60 and "Мария".encode("utf8") not in row["ciphertext"] and b"+79990000001" not in row["ciphertext"],"PII plaintext detected")
            check(row["site"]==SITE and row["receipt"]==receipt,"wrong provenance")
            denied=subprocess.run(["php",str(private/"console.php"),"read",str(private),receipt],capture_output=True,text=True)
            check(denied.returncode==2 and "Мария Тест" not in denied.stdout,"sensitive read must require opt-in")
            authorized=subprocess.run(["php",str(private/"console.php"),"read",str(private),receipt,"--confirm-sensitive"],capture_output=True,text=True)
            check(authorized.returncode==0 and "Мария Тест" in authorized.stdout,"explicit local-only decrypt path broken")
            source=__import__('json').loads(authorized.stdout)['contact']['observed_source']
            check(source['site']==SITE and source['entry_hint']=='homepage' and source['traffic_channel']=='unverified','source site must be verified, channel must remain unknown')
            check(source['utm']=={'utm_source':'yandex','utm_medium':'cpc','utm_campaign':'legal_ad'} and source['utm_transport']=='query','real query UTM not persisted')
            check("Мария Тест" not in (subprocess.check_output(["php",str(private/"console.php"),"status",str(private)],text=True)),"CLI count must not expose PII")
            status,final2,body2=call(p,port,values=good)
            check(status==200 and final2==final and count(db)==1,"idempotency failed")
            changed={**good,"problem":"Отличающееся синтетическое содержимое заявления для проверки конфликтов"}
            status,_,body=call(p,port,values=changed)
            check(status==409 and count(db)==1,"idempotency conflict not denied")
            # New browser cannot view receipt from another session
            status,_,body=call(opener(),port,extra_headers=None)
            check(status==200 and "сохранить обращение" in body.lower(),"new session broken")
            status,_,body=call(opener(),port,host="evil.example")
            check(status==503 and "сохранить обращение" not in body.lower(),"wrong hostname accepted")
            # Five unique requests per synthetic test IP / 20min; max sixth blocked.
            for i in range(4):
                f=valid(form(p,port))
                f["phone"]=f"+799900000{10+i}"
                st,_,out=call(p,port,values=f)
                check(st==200 and "сохранено на сервере" in out.lower(),f"valid request {i} failed {st}")
            check(count(db)==5,"expected 5 stored synthetic requests")
            overflow=valid(form(p,port));overflow["phone"]="+79990000099"
            st,_,out=call(p,port,values=overflow)
            check(st==429 and "не сохранено" in out.lower(),"rate control not enforced")
            check(count(db)==5,"6th attempt was recorded")
            alert_env={**os.environ, "OLEG_ALERT_TEST_MODE":"1", "OLEG_ALERT_TEST_SINK":str(home/"alert-test-sink.jsonl")}
            def alert(mode):
                return subprocess.run(["php",str(private/"alert.php"),str(private),mode],env=alert_env,capture_output=True,text=True)
            dry=alert("--dry-run")
            check(dry.returncode==0 and '"pending_total":5' in dry.stdout,"pending digest failed")
            check(not (home/"alert-test-sink.jsonl").exists(),"dry-run sent mail")
            first=alert("--check")
            check(first.returncode==0 and "ACCEPTED_BY_MAIL_TRANSPORT" in first.stdout,"first alert missing")
            check(len((home/"alert-test-sink.jsonl").read_text().splitlines())==1,"expected one privacy-safe alert")
            repeat=alert("--check")
            check(repeat.returncode==0 and "ALERT_NOOP" in repeat.stdout,"duplicate alert sent")
            test_mail=alert("--test-mail")
            check(test_mail.returncode==0 and len((home/"alert-test-sink.jsonl").read_text().splitlines())==2,"test mail not sandboxed")
            messages=(home/"alert-test-sink.jsonl").read_text()
            check("Мария" not in messages and "79990000001" not in messages,"notification leaked applicant data")
            db.execute("UPDATE requests SET status='crm_verified'");db.commit()
            check(alert("--check").returncode==0,"cannot reset alert state after clearing queue")
            db.execute("UPDATE requests SET status='awaiting_manual_review' WHERE receipt=?",(receipt,));db.commit()
            newalert=alert("--check")
            check(newalert.returncode==0 and len((home/"alert-test-sink.jsonl").read_text().splitlines())==3,"fresh alert not triggered after clearance")
            snapshot=subprocess.run(["php",str(private/"backup.php"),str(private),"backup"],capture_output=True,text=True)
            check(snapshot.returncode==0 and "BACKUP_INTEGRITY_RESTORE_VERIFIED" in snapshot.stdout,"encrypted snapshot failed to restore")
            verify=subprocess.run(["php",str(private/"backup.php"),str(private),"verify"],capture_output=True,text=True)
            check(verify.returncode==0 and "BACKUP_INTEGRITY_RESTORE_VERIFIED" in verify.stdout,"backup verification failed")
            backups=list((private/"backups").glob("*.sqlite"))
            keycopies=list((private/"backups").glob("*.key"))
            check(len(backups)==len(keycopies)==1,"expected one isolated backup/key pair")
            check((backups[0].stat().st_mode & 0o777)==0o600 and (keycopies[0].stat().st_mode & 0o777)==0o600,"backup/key permissions unsafe")
            # Missing storage must return fail-closed, not a false success
            db.close()
            (private/"intake.sqlite").rename(private/"intake.sqlite.missing")
            st,_,out=call(p,port)
            check(st==503 and "обращение не сохранено" in out.lower() and "временно" in out.lower(),"no-db GET not fail-closed")
            print("V17_INTAKE_ISOLATED_TESTS_PASS: csrf,origin,consent,honeypot,encrypted_commit,receipt,idempotency,conflict,rate_limit,no_db,permissions,wrong_host")
            print("TESTS_SYNTHETIC_ONLY; PRODUCTION_WRITES=0; REAL_CRM_LEADS=0")
        finally:
            server.terminate()
            try:server.wait(timeout=4)
            except subprocess.TimeoutExpired:server.kill()
if __name__=="__main__":main()
