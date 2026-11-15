"""Offline protocol/authorization tests. No OS, network or real keyboard action."""
import io
import json
from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0,str(Path(__file__).parent))
from one_desktop_owner_mcp import OneDesktopOwnerMcp, OwnerRefused, process, serve_stdio, _strict_json, windows_owner_consent

PROJECT="a"*32
SID="b"*32
PLAN="c"*32

m=types.ModuleType("desktop_goal_one")
def safe_navigation_labels(controls):
    return [x['label'] for x in controls if x.get('type')==50000 and x.get('label') not in ('Пароль','Отправить')]
m.safe_navigation_labels=safe_navigation_labels
sys.modules['desktop_goal_one']=m
m2=types.ModuleType("desktop_script_one")
def parse_safe_desktop_script(s):
    if 'Удалить' in s or 'PowerShell' in s or not s.startswith('Посмотри окно'):
        raise ValueError('DESKTOP_COMMAND_NOT_ALLOWED')
    return [{'op':'observe'}]
m2.parse_safe_desktop_script=parse_safe_desktop_script
sys.modules['desktop_script_one']=m2

class Store:
    def project(self,project):
        if project != PROJECT: raise ValueError('PROJECT_NOT_FOUND')

class Desktop:
    def __init__(self):
        self.store=Store()
        self.apps=frozenset(('notepad.exe',))
        self.session=None
        self.calls=[]
    def capabilities(self):
        return {'configured':True}
    def windows(self, project):
        self.store.project(project)
        return [{'app':'notepad.exe','pid':42,'handle':123,'width':500,'height':200},
                {'app':'sensitive.exe','pid':99,'handle':456,'width':500,'height':300}]
    def attach(self,project,app,pid,handle):
        self.store.project(project)
        self.calls.append(('attach',app,pid,handle))
        self.session={'id':SID, 'app':app}
        return {'session_id':SID}
    def status(self,project):
        self.store.project(project)
        return {'session':self.session}
    def action(self,project,sid,op):
        if op!='observe' or sid!=SID: raise ValueError('INVALID_CALL')
        return {'result':{'controls':[{'type':50000,'label':'Отчёты'},
                                      {'type':50000,'label':'Пароль'},
                                      {'type':50004,'label':'Секретные данные'},
                                      {'type':50000,'label':'Отправить'}]}}
    def close(self,project,sid):
        self.session=None
        return {'closed':True}

class Scripts:
    def __init__(self):
        self.starts=[]
    def prepare(self,project,sid,script):
        return {'id':PLAN}
    def start(self,project,sid,plan,script):
        self.starts.append((project,sid,plan,script))
        return {'state':'RUNNING','id':plan,'no_auto_retry':True}
    def get(self,project,ident):
        return {'state':'DONE','id':ident, 'no_auto_retry':True}

class OneDesktopTests(unittest.TestCase):
    def setUp(self):
        self.desktop=Desktop();self.scripts=Scripts()
        self.yes=False;self.prompts=[]
        def confirm(title,detail):
            self.prompts.append((title,detail))
            return self.yes
        self.bridge=OneDesktopOwnerMcp(self.desktop,self.scripts,PROJECT,confirm)
    def attach(self):
        self.yes=True
        self.bridge.call('one_desktop_windows',{})
        return self.bridge.call('one_desktop_attach',{'app':'notepad.exe','pid':42,'handle':123})

    def test_protocol_and_static_tools(self):
        x=process({'jsonrpc':'2.0','id':1,'method':'initialize','params':{}},self.bridge)
        self.assertEqual(x['result']['capabilities']['tools']['listChanged'],False)
        self.assertEqual(process({'jsonrpc':'2.0','id':2,'method':'tools/list'},self.bridge)['result']['tools'][0]['name'],'one_desktop_status')
        self.assertEqual(process({'jsonrpc':'2.0','id':3,'method':'ping'},self.bridge)['result'],{})
        self.assertIsNone(process({'jsonrpc':'2.0','method':'notifications/initialized'},self.bridge))
    def test_no_unapproved_window_listed(self):
        ws=self.bridge.call('one_desktop_windows',{})['windows']
        self.assertEqual(len(ws),1)
        self.assertEqual(ws[0]['app'],'notepad.exe')
    def test_cannot_attach_to_unlisted_app_or_pid(self):
        with self.assertRaises(OwnerRefused):
            self.bridge.call('one_desktop_attach',{'app':'notepad.exe','pid':42,'handle':123})
        self.bridge.call('one_desktop_windows',{})
        with self.assertRaises(OwnerRefused):
            self.bridge.call('one_desktop_attach',{'app':'notepad.exe','pid':1,'handle':123})
        with self.assertRaises(OwnerRefused):
            self.bridge.call('one_desktop_attach',{'app':'sensitive.exe','pid':99,'handle':456})
    def test_denied_consent_does_not_attach_or_execute(self):
        self.bridge.call('one_desktop_windows',{})
        with self.assertRaises(OwnerRefused):
            self.bridge.call('one_desktop_attach',{'app':'notepad.exe','pid':42,'handle':123})
        self.assertEqual(self.desktop.calls,[])
        self.attach()
        self.yes=False
        with self.assertRaises(OwnerRefused):
            self.bridge.call('one_desktop_execute',{'script':'Посмотри окно'})
        self.assertEqual(self.scripts.starts,[])
    def test_observe_redacts_private_labels(self):
        self.attach()
        result=self.bridge.call('one_desktop_observe',{})
        self.assertEqual(result['navigation_labels'],['Отчёты'])
    def test_execute_requires_fresh_consent_and_safe_grammar(self):
        self.attach()
        self.yes=True
        with self.assertRaises(ValueError):
            self.bridge.call('one_desktop_execute',{'script':'Удалить всё'})
        self.assertEqual(len(self.prompts),1)
        result=self.bridge.call('one_desktop_execute',{'script':'Посмотри окно'})
        self.assertEqual(result['state'],'RUNNING')
        self.assertEqual(len(self.scripts.starts),1)
        self.assertIn('Посмотри окно',self.prompts[-1][1])
    def test_no_shell_or_unlisted_tool(self):
        for name in ('run_command','execute_powershell','delete_file','one_desktop_shell'):
            with self.assertRaises(OwnerRefused):self.bridge.call(name,{})
    def test_invalid_kwargs_fail_closed(self):
        for name,kwargs in [('one_desktop_status',{'project':PROJECT}),('one_desktop_execute',{'script':'Посмотри окно','approved':True}),('one_desktop_attach',{'app':'notepad.exe','pid':42,'handle':123,'approved':True})]:
            with self.assertRaises(OwnerRefused):self.bridge.call(name,kwargs)
    def test_status_and_detach(self):
        self.attach()
        self.assertTrue(self.bridge.call('one_desktop_status',{})['selected_window'])
        self.assertTrue(self.bridge.call('one_desktop_detach',{})['closed'])
        with self.assertRaises(OwnerRefused):self.bridge.call('one_desktop_observe',{})
    def test_protocol_outputs_only_json(self):
        requests=[{'jsonrpc':'2.0','id':1,'method':'tools/list'},
                  {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'one_desktop_status','arguments':{}}}]
        inp=io.StringIO('\n'.join(json.dumps(x) for x in requests)+'\n')
        out=io.StringIO()
        serve_stdio(self.bridge,inp,out)
        output=[json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(len(output),2)
        self.assertFalse(output[1]['result']['isError'])
    def test_duplicate_json_key_is_refused(self):
        with self.assertRaises(OwnerRefused):_strict_json('{"a":1,"a":2}')
    def test_nonwindows_consent_denied(self):
        import os
        if os.name!='nt':self.assertFalse(windows_owner_consent('ok','ok'))
    def test_invalid_jsonrpc_tool_requests_fail_closed(self):
        calls=[
            {'jsonrpc':'2.0','id':20,'method':'tools/call','params':{'name':'one_desktop_execute','arguments':{'script':'Посмотри окно','approved':True}}},
            {'jsonrpc':'2.0','id':21,'method':'tools/call','params':{'name':'execute_shell','arguments':{'command':'dir'}}},
            {'jsonrpc':'2.0','id':22,'method':'tools/call','params':{'name':'one_desktop_status','arguments':{'secret':'x'}}},
        ]
        for request in calls:
            with self.subTest(name=request['params']['name']):
                result=process(request,self.bridge)
                self.assertIs(result['result']['isError'],True)
                self.assertNotIn('secret',str(result).lower())
                self.assertEqual(self.desktop.calls,[])

    def test_unknown_protocol_method_does_not_execute(self):
        response=process({'jsonrpc':'2.0','id':50,'method':'tools/execute'},self.bridge)
        self.assertEqual(response['error']['message'],'METHOD_NOT_FOUND')
        self.assertEqual(self.desktop.calls,[])

    def test_wrong_project_not_accepted(self):
        with self.assertRaises(ValueError):OneDesktopOwnerMcp(self.desktop,self.scripts,'b'*32,lambda *a:True)

if __name__=='__main__':unittest.main()
