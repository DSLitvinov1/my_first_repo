import json
import io
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer

import local_qwen as q
from fallback_controller import MockClaudeToLocalQwen
from offline_router import OfflineScriptedProvider, QuotaExhausted, AuthenticationFailure, TemporaryFailure, Request


def reply(model="qwen3:4b", text="model answer", **extra):
    return json.dumps(dict(model=model, response=text, done=True, **extra)).encode()


class Tests(unittest.TestCase):
    def setUp(self):
        self.budget=q.LocalBudget(max_attempts=3,max_reserved_units=16000)
        self.adapter=q.LocalQwenAdapter(q.LocalQwenConfig(enabled=True),self.budget)

    def test_default_disabled(self):
        with self.assertRaises(q.LocalProviderDisabled):
            q.LocalQwenAdapter(q.LocalQwenConfig(), q.LocalBudget()).generate("hi")

    def test_positive_mock_response(self):
        with patch.object(q,"_loopback_post",return_value=reply()) as send:
            result=self.adapter.generate('test prompt')
        self.assertEqual(result.text,"model answer")
        self.assertTrue(result.local_only)
        self.assertFalse(result.published)
        self.assertEqual(self.budget.attempts,1)
        args=send.call_args.args
        self.assertEqual(args[0],q.ENDPOINT)
        self.assertEqual(args[2],30)
        obj=json.loads(args[1]); self.assertEqual(obj['model'],'qwen3:4b'); self.assertFalse(obj['stream'])
        self.assertEqual(obj['options']['num_predict'],256)
        self.assertNotIn('api_key',obj)

    def test_limit_and_no_retry(self):
        with patch.object(q,"_loopback_post",return_value=reply()) as send:
            for i in range(3): self.adapter.generate('short')
            with self.assertRaises(q.LocalBudgetExceeded): self.adapter.generate('short')
        self.assertEqual(send.call_count,3)

    def test_budget_char_units_stop(self):
        small=q.LocalQwenAdapter(q.LocalQwenConfig(enabled=True),q.LocalBudget(max_reserved_units=1024))
        with patch.object(q,"_loopback_post") as send:
            with self.assertRaises(q.LocalBudgetExceeded):small.generate('prompt long enough')
            send.assert_not_called()

    def test_timeout_consumes_attempt(self):
        with patch.object(q,"_loopback_post",side_effect=q.LocalProviderUnknownResult('timeout')) as send:
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')
            self.assertEqual(self.budget.attempts,1)
            self.assertEqual(send.call_count,1)

    def test_duplicate_json_key_rejected(self):
        data=b'{"model":"qwen3:4b","model":"qwen3:4b","response":"ok","done":true}'
        with patch.object(q,"_loopback_post",return_value=data):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_wrong_model_rejected(self):
        with patch.object(q,"_loopback_post",return_value=reply(model='cloud:latest')):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_empty_reply_rejected(self):
        with patch.object(q,"_loopback_post",return_value=reply(text='  ')):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_incomplete_rejected(self):
        with patch.object(q,"_loopback_post",return_value=reply(done_reason='length')):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_done_false_rejected(self):
        with patch.object(q,"_loopback_post",return_value=b'{"model":"qwen3:4b","response":"ok","done":false}'):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_non_object_rejected(self):
        with patch.object(q,"_loopback_post",return_value=b'[]'):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_bad_json_rejected(self):
        with patch.object(q,"_loopback_post",return_value=b'{bad'):
            with self.assertRaises(q.LocalProviderUnknownResult):self.adapter.generate('hi')

    def test_max_prompt_rejected_without_reservation(self):
        with self.assertRaises(ValueError):self.adapter.generate('x'*12001)
        self.assertEqual(self.budget.attempts,0)

    def test_blank_prompt_rejected(self):
        with self.assertRaises(ValueError):self.adapter.generate(' ')

    def test_no_arbitrary_model(self):
        with self.assertRaises(ValueError):q.LocalQwenConfig(enabled=True,model='deepseek-v4')

    def test_no_long_timeout(self):
        with self.assertRaises(ValueError):q.LocalQwenConfig(enabled=True,timeout_seconds=900)

    def test_bool_int_bypass_blocked(self):
        with self.assertRaises(ValueError):q.LocalQwenConfig(enabled=True,max_output_tokens=True)
        with self.assertRaises(ValueError):q.LocalBudget(max_attempts=True)

    def test_nonlocal_url_fails_before_network(self):
        with self.assertRaises(q.LocalProviderError):q._loopback_post('https://api.deepseek.com',b'{}',1)

    def test_mock_quota_fallback(self):
        with patch.object(q,"_loopback_post",return_value=reply()):
            r=MockClaudeToLocalQwen(OfflineScriptedProvider('claude',[QuotaExhausted('limit')]),self.adapter).run(Request('task01','question'))
        self.assertEqual((r.provider,r.local_fallback,r.mock_primary),('qwen3:4b',True,True))

    def test_mock_primary_success_no_local_call(self):
        with patch.object(q,"_loopback_post") as send:
            r=MockClaudeToLocalQwen(OfflineScriptedProvider('claude',['ok']),self.adapter).run(Request('task02','question'))
        self.assertEqual(r.provider,'claude')
        send.assert_not_called()

    def test_no_fallback_on_auth(self):
        with patch.object(q,"_loopback_post") as send:
            with self.assertRaises(AuthenticationFailure):MockClaudeToLocalQwen(OfflineScriptedProvider('claude',[AuthenticationFailure('bad')]),self.adapter).run(Request('task03','question'))
        send.assert_not_called()

    def test_no_fallback_on_timeout(self):
        with patch.object(q,"_loopback_post") as send:
            with self.assertRaises(TemporaryFailure):MockClaudeToLocalQwen(OfflineScriptedProvider('claude',[TemporaryFailure('err')]),self.adapter).run(Request('task04','question'))
        send.assert_not_called()

    def test_mock_only_primary(self):
        class Bad(OfflineScriptedProvider):pass
        with self.assertRaises(TypeError):MockClaudeToLocalQwen(Bad('claude',[]),self.adapter)

    def test_budget_parallel_reservation(self):
        budget=q.LocalBudget(max_attempts=5,max_reserved_units=40000)
        good=[]
        def work():
            try:budget.reserve(5);good.append(True)
            except q.LocalBudgetExceeded:pass
        jobs=[threading.Thread(target=work) for _ in range(50)]
        for job in jobs:job.start()
        for job in jobs:job.join()
        self.assertEqual((len(good),budget.attempts,budget.reserved_units),(5,5,25))

    def test_redirect_is_rejected(self):
        with self.assertRaises(q.LocalProviderUnknownResult):q._NoRedirect().redirect_request(None,None,302,'moved',{},'http://google.com')

    def test_no_proxy_handler_when_opening(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'{}'
        class Opener:
            def open(self,*args,**kwargs):return Response()
        with patch.object(q,'build_opener',return_value=Opener()) as build:
            self.assertEqual(q._loopback_post(q.ENDPOINT,b'{}',1),b'{}')
        self.assertTrue(any(isinstance(a,q.ProxyHandler) and a.proxies=={} for a in build.call_args.args))

    def test_oversize_response_rejected(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'x'*(q.MAX_REPLY_BYTES+1)
        class Opener:
            def open(self,*args,**kwargs):return Response()
        with patch.object(q,'build_opener',return_value=Opener()):
            with self.assertRaises(q.LocalProviderUnknownResult):q._loopback_post(q.ENDPOINT,b'{}',1)

    def test_local_http_integration(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                body=self.rfile.read(length)
                obj=json.loads(body)
                self.server.received=obj
                data=reply(model=obj['model'],text='loopback-ok')
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.end_headers()
                self.wfile.write(data)
            def log_message(self,*args):pass
        httpd=HTTPServer(('127.0.0.1',0),Handler)
        t=threading.Thread(target=httpd.serve_forever,daemon=True)
        t.start()
        try:
            url=f'http://127.0.0.1:{httpd.server_port}/api/generate'
            # Patch only immutable constant to point to temporary loopback fixture.
            with patch.object(q,'ENDPOINT',url):
                self.assertEqual(self.adapter.generate('test').text,'loopback-ok')
            self.assertEqual(httpd.received['model'],'qwen3:4b')
        finally:httpd.shutdown();httpd.server_close();t.join()

    def test_no_external_transport_written(self):
        import inspect
        self.assertNotIn('api.deepseek.com',inspect.getsource(q))
        self.assertNotIn('api.anthropic.com',inspect.getsource(q))
        self.assertNotIn('dashscope.aliyuncs.com',inspect.getsource(q))


if __name__=='__main__':unittest.main()
