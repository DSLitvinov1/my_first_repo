"""Independent REVIEW-only PostgreSQL offline authorization negative.

Uses only an ephemeral CI PostgreSQL database nf_test and REVIEW fixture records.
No real host, tokens, Qwen, paid API, or user project data.
A passing negative means the offline prototype is NOT an authorization boundary.
"""
import hashlib
import os
from pathlib import Path
import secrets
import sys

import psycopg

HOST_DIR = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(HOST_DIR))
from offline_cas import OfflineCAS, OfflineBoundaryError

def main():
    dsn = os.environ["REVIEW_SYNTHETIC_PG_DSN"]
    with psycopg.connect(dsn, autocommit=True) as conn:
        schema = (HOST_DIR / "schema_v1.sql").read_text(encoding="utf8")
        conn.execute(schema)
        assert conn.execute("SELECT current_database()").fetchone()[0] == "nf_test"
        # Empty/unset flag refuses prototype operations at constructor.
        try:
            OfflineCAS(conn)
        except OfflineBoundaryError:
            print("REVIEW_OFFLINE_MODE_UNSET=DENIED")
        else:
            raise AssertionError("Offline marker unexpectedly optional")

        # Ordinary PostgreSQL session GUC is settable by its own client.
        conn.execute("SELECT set_config('neurofactory.offline_fixture_mode','on',false)")
        assert conn.execute("SELECT current_setting('neurofactory.offline_fixture_mode')").fetchone()[0] == "on"
        candidate = OfflineCAS(conn)
        task = "NF-DEV-05-Q988"
        request = "a"*32
        worker = "unverified-client"
        conn.execute("""
          INSERT INTO nf_task(task_id,project_id,input_core_sha40,
                              source_file_sha256,input_task_sha256)
          VALUES (%s,%s,%s,%s,%s)
        """, (task,"review-only","1"*40,"2"*64,"3"*64))
        denied = candidate.claim(task,worker,request)
        assert denied["status"] == "BLOCKED"
        print("REVIEW_DEFAULT_FIXTURE_AUTHORIZATION=BLOCKED")

        # Same test DB client can directly change a boolean field; there is no
        # issuer proof or per-worker authenticated approval attached to it.
        conn.execute("UPDATE nf_task SET fixture_authorized=TRUE WHERE task_id=%s", (task,))
        second = candidate.claim(task,worker,request)
        assert second["status"] == "CLAIMED"
        assert second["lease_epoch"] == 1
        print("REVIEW_CLIENT_ENABLED_OWN_OFFLINE_FLAG=TRUE")
        print("REVIEW_DB_CLIENT_SELF_AUTHORIZED_TEST_TASK=CLAIMED")
        # Raw token is purposely not logged or returned to external service.
        conn.execute("SELECT set_config('neurofactory.offline_fixture_mode','off',false)")
        # The constructor flag is not rechecked before method calls.
        state = candidate.public_state(task)
        assert state["status"] == "LEASED"
        assert state["verified"] is False and state["actions_allowed"] is False
        print("REVIEW_MARKER_DISABLED_AFTER_INIT=METHOD_STILL_READABLE")
        print("REVIEW_PUBLIC_STATE=UNVERIFIED_ACTIONS_FALSE")
        print("REVIEW_ACTUAL_ISSUER_AUTHENTICATION=NOT_IMPLEMENTED")
        print("REVIEW_RESULT=TEST_FIXTURE_MODE_NOT_REAL_TRUST_BOUNDARY")

if __name__ == "__main__":
    main()
