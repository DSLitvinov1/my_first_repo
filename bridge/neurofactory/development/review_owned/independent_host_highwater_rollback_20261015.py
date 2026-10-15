"""Independent REVIEW-only ephemeral PostgreSQL highwater negative.
A test database owner can rewrite both head and history; check that an external
old pin detects it, while a self-chosen new pin never attests provenance.
No production DB, owner credentials, model or live authorization.
"""
import os
from pathlib import Path
import sys
import psycopg
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
from offline_highwater import OfflineHighwater
root=Path(sys.argv[1])
with psycopg.connect(os.environ["REVIEW_EPHEMERAL_PG_DSN"],autocommit=True) as c:
 assert c.execute("SELECT current_database()").fetchone()[0]=="nf_test"
 c.execute((root/"schema_v1.sql").read_text())
 c.execute((root/"offline_highwater_schema.sql").read_text())
 c.execute("SELECT set_config('neurofactory.offline_fixture_mode','on',false)")
 task="NF-DEV-05-Q996"
 c.execute("""INSERT INTO nf_task(task_id,project_id,input_core_sha40,source_file_sha256,input_task_sha256)
 VALUES(%s,%s,%s,%s,%s)""",(task,"review-project","a"*40,"b"*64,"c"*64))
 ledger=OfflineHighwater(c)
 genesis="0"*64
 h1="1"*64; h2="2"*64
 assert ledger.append(task,1,genesis,h1)["status"]=="RECORDED_TEST_ONLY"
 assert ledger.append(task,2,h1,h2)["status"]=="RECORDED_TEST_ONLY"
 assert ledger.observe(task,2,h2)["reported_head_matches_supplied_pin"] is True
 print("REVIEW_TWO_MONOTONIC_APPENDS=TEST_ONLY_RECORDED")
 assert ledger.append(task,2,h1,"3"*64)["status"]=="BLOCKED"
 assert ledger.append(task,3,h1,"3"*64)["status"]=="BLOCKED"
 print("REVIEW_DUPLICATE_SEQUENCE_AND_STALE_PARENT=BLOCKED")
 # Attacker with the database-owner test credentials changes DB rows directly,
 # unlike a genuine independent, permission-separated issuer.
 c.execute("DELETE FROM nf_offline_chain_event WHERE task_id=%s AND sequence=2",(task,))
 c.execute("UPDATE nf_offline_chain_head SET last_sequence=1,last_digest_sha256=%s WHERE task_id=%s",(h1,task))
 denied=ledger.observe(task,2,h2)
 assert denied["reported_head_matches_supplied_pin"] is False
 print("REVIEW_ROLLBACK_AGAINST_PRIOR_INDEPENDENT_PIN=DETECTED")
 # Passing a forged, newly chosen expected pin is NOT origin attestation.
 local=ledger.observe(task,1,h1)
 assert local["reported_head_matches_supplied_pin"] is True
 assert local["independent_pin_source_authenticated"] is False
 assert local["publisher_allowed"] is False
 assert local["automatic_retry_allowed"] is False
 print("REVIEW_SELF_REPINNED_ROLLBACK=LOCAL_MATCH_ONLY_NO_AUTH")
 assert ledger.append(task,2,h1,"4"*64)["status"]=="RECORDED_TEST_ONLY"
 fork=ledger.observe(task,2,"4"*64)
 assert fork["reported_head_matches_supplied_pin"] is True
 assert fork["independent_pin_source_authenticated"] is False
 assert ledger.observe(task,2,h2)["reported_head_matches_supplied_pin"] is False
 print("REVIEW_AFTER_PRIVILEGED_ROLLBACK_FORK=RECORDED_TEST_ONLY")
 print("REVIEW_SEPARATE_PROTECTED_ISSUER_OR_APPEND_ONLY_OS_ROLE=ABSENT")
