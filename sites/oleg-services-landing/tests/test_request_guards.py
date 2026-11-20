from __future__ import annotations
from contextlib import contextmanager
from http.cookiejar import CookieJar
from pathlib import Path
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
PORT=18166
ORIGIN=f"http://127.0.0.1:{PORT}"
PUBLIC_ORIGIN="https://legal-stage.example"
def call(opener,path,method="GET",data=None,origin=PUBLIC_ORIGIN):
    headers={"Accept":"application/json"}
    if data is not None:
        headers["Content-Type"]="application/json"
    if origin is not None:
        headers["Origin"]=origin
    req=urllib.request.Request(ORIGIN+path,method=method,data=json.dumps(data).encode() if data is not None else None,headers=headers)
    try:
        with opener.open(req,timeout=3) as r:
            return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read())
with tempfile.TemporaryDirectory(prefix="oleg-b24-guards-") as temp:
    env=os.environ.copy()
    env.update({
        "OLEG_SERVICES_PUBLIC_ORIGIN":PUBLIC_ORIGIN,
        "OLEG_SERVICES_STATE_DIR":str(Path(temp)/"private-state"),
        "OLEG_BITRIX_WEBHOOK_URL":"https://b24-xlzm11.bitrix24.ru/rest/1/TEST_FAKE_NO_NETWORK_ACCESS/",
        "OLEG_BITRIX_CATEGORY_ID":"2",
        "OLEG_BITRIX_ASSIGNED_BY_ID":"1",
    })
    server=subprocess.Popen(["php","-S",f"127.0.0.1:{PORT}","-t",str(ROOT)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
    try:
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
        for i in range(30):
            try:
                status,nonce=call(opener,"/api/nonce.php")
                break
            except Exception:
                time.sleep(.1)
        else:
            raise RuntimeError("PHP local test server failed")
        assert status==200 and len(nonce["token"])==48
        valid={
            "csrf":nonce["token"],"topic":"Наследство",
            "service":"free","name":"Тестовый пользователь","phone":"+7 (999) 000-00-00",
            "consent":True,"request_id":"a15e3df2-5620-4903-9df9-60c3d72f2b33",
            "website":"","page":"/","utm_source":"unit_test",
        }
        status,body=call(opener,"/api/lead.php","POST",valid,origin="https://evil.invalid")
        assert (status,body["status"])==(403,"forbidden_origin")
        altered={**valid,"csrf":"wrong"}
        status,body=call(opener,"/api/lead.php","POST",altered)
        assert (status,body["status"])==(403,"invalid_token")
        altered={**valid,"phone":"111"}
        status,body=call(opener,"/api/lead.php","POST",altered)
        assert (status,body["status"])==(422,"invalid_fields")
        status,newtoken=call(opener,"/api/nonce.php")
        assert status==200
        altered={**valid,"csrf":newtoken["token"],"service":"unapproved"}
        status,body=call(opener,"/api/lead.php","POST",altered)
        assert (status,body["status"])==(422,"invalid_fields")
        # An invalid payload must not reach Bitrix24 or create state files.
        assert not list((Path(temp)/"private-state").glob("submission-*")) if (Path(temp)/"private-state").exists() else True
        print("PASS: PHP 200 nonce, 403 hostile origin, 403 CSRF, 422 invalid phone; no CRM POST")
    finally:
        server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
