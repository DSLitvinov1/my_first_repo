"""Offline safety tests: no npm installation, filesystem writes or agent invocation."""
import json
import unittest
from one_files_dc_mcp import (Denied, PACKAGE, allowed_tool_names, safe_windows_path,
                              verify_workspace, validate_tool_call, filter_server_response)
from owner_free_dc_config import make_free_config

ROOT = r'C:\ChatGPTProjects\ONE-DC-Isolated'
COMMON = dict(
    python_exe=r'C:\Python312\python.exe',
    workbench=r'C:\ChatGPTProjects\ONE-Candidate\workbench',
    playwright_config=r'C:\ChatGPTProjects\ONE-Candidate\playwright_owner_mcp.json',
    root=r'C:\ChatGPTProjects\ONE-Candidate\projects',
    data=r'C:\ChatGPTProjects\ONE-Candidate\data',
    project='auto', apps='notepad.exe,chrome.exe', workspace=ROOT)

class FreeDCTests(unittest.TestCase):
    def test_exact_pinned_package_and_stdio_only(self):
        self.assertEqual(PACKAGE, '@wonderwhy-er/desktop-commander@0.3.3')
        m=make_free_config(**COMMON)
        self.assertEqual(set(m['mcpServers']), {'one-browser','one-desktop','one-files'})
        f=m['mcpServers']['one-files']
        self.assertEqual(f['command'], COMMON['python_exe'])
        self.assertTrue(f['args'][0].endswith('one_files_dc_mcp.py'))
        self.assertNotIn('--allow-write', f['args'])
        self.assertNotIn('remote', json.dumps(m).lower())
    def test_writes_require_opt_in(self):
        m=make_free_config(**COMMON,allow_write=True)
        self.assertIn('--allow-write',m['mcpServers']['one-files']['args'])
        self.assertNotIn('start_process', allowed_tool_names(True))
    def test_read_and_write_within_workspace(self):
        read={'name':'read_file','arguments':{'path':ROOT + r'\site\index.html'}}
        validate_tool_call(read,ROOT,False)
        write={'name':'edit_block','arguments':{'file_path':ROOT + r'\site\index.html',
                'old_string':'a','new_string':'b'}}
        with self.assertRaises(Denied):validate_tool_call(write,ROOT,False)
        validate_tool_call(write,ROOT,True)
    def test_rejects_terminal_escape_and_remote(self):
        for name in ('start_process','kill_process','interact_with_process',
                     'get_config','set_config_value','search_files','remote'):
            with self.subTest(name=name),self.assertRaises(Denied):
                validate_tool_call({'name':name,'arguments':{'path':ROOT + r'\x'}},ROOT,True)
    def test_rejects_out_of_workspace_and_credential_paths(self):
        paths=[r'C:\Windows\System32\drivers\etc\hosts',
               r'C:\ChatGPTProjects\ONE-DC-Isolated\..\Elsewhere\x',
               r'C:\ChatGPTProjects\ONE-DC-Isolated2\site.html',
               r'\\server\share\secret',
               'https://potrebpravo.ru/index.html',
               ROOT + r'\.env',ROOT + r'\.git\config',ROOT + r'\x.pfx']
        for path in paths:
            with self.subTest(path=path),self.assertRaises(Denied):
                safe_windows_path(path,ROOT)
    def test_rejects_extra_argument_smuggling(self):
        for args in ({'path':ROOT + r'\x','command':'whoami'},
                     {'path':'https://example.com'},
                     {'path':ROOT + r'\x','isUrl':True}):
            with self.subTest(args=args),self.assertRaises(Denied):
                validate_tool_call({'name':'read_file','arguments':args},ROOT,False)
    def test_tool_list_is_filtered_in_read_only_and_write_mode(self):
        payload = {'id': 9, 'result': {'tools': [
            {'name': 'read_file'}, {'name': 'start_process'}, {'name': 'edit_block'}]}}
        pending = {9}
        filtered = filter_server_response(payload, pending, False)
        self.assertEqual([t['name'] for t in filtered['result']['tools']], ['read_file'])
        self.assertNotIn(9, pending)
        payload = {'id': 10, 'result': {'tools': [
            {'name': 'read_file'}, {'name': 'start_process'}, {'name': 'edit_block'}]}}
        self.assertEqual([t['name'] for t in filter_server_response(payload, {10}, True)['result']['tools']],
                         ['read_file','edit_block'])
    def test_windows_alternate_data_stream_and_depth_refused(self):
        with self.assertRaises(Denied):
            safe_windows_path(ROOT + r'\index.html:passwords', ROOT)
        for bad in (-1, 4, 99999, '100', True):
            with self.assertRaises(Denied):
                validate_tool_call({'name':'list_directory','arguments':{'path':ROOT, 'depth':bad}}, ROOT, False)
    def test_requires_dedicated_isolated_workspace(self):
        for p in [r'C:\Users\Owner',r'C:\ChatGPTProjects\ONE\test',
                  r'D:\Temp\ONE-Demo',r'C:\ChatGPTProjects\ONE-DC-Isolated\..\foo']:
            with self.subTest(p=p),self.assertRaises(Denied):verify_workspace(p)
        self.assertEqual(verify_workspace(ROOT), ROOT)

if __name__=='__main__':unittest.main(verbosity=2)
