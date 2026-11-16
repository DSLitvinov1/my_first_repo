import json
import os
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path
from metadata_guard import replace_once, prepare, apply_edits

DOC = '<!doctype html><html lang="ru"><head><title>Старый заголовок</title><meta name="description" content="Старое описание страницы" /><meta name="robots" content="index,follow"></head><body>Заявка</body></html>'

class MetadataGuardTests(unittest.TestCase):
    def plan(self):
        return {"sites":[{"host":"potrebpravo.ru","changes":[{
            "path":"index.html","expected":{"title":"Старый заголовок","description":"Старое описание страницы"},
            "proposed":{"title":"Новый заголовок","description":"Новое описание юридической услуги для посетителя"}
        }]}]}
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.parent=Path(self.tmp.name)
        self.root=self.parent/"potrebpravo.ru"/"public_html"
        self.root.mkdir(parents=True)
        (self.root/"index.html").write_text(DOC,encoding="utf-8")
    def tearDown(self):
        self.tmp.cleanup()
    def test_dryrun_no_write_and_guarded_apply(self):
        edits=prepare(self.plan(),self.parent)
        self.assertIn("Старый заголовок",(self.root/"index.html").read_text(encoding="utf-8"))
        backup,count=apply_edits(edits,self.parent)
        self.assertEqual(count,1)
        new=(self.root/"index.html").read_text(encoding="utf-8")
        self.assertIn("<title>Новый заголовок</title>",new)
        self.assertIn('content="Новое описание юридической услуги для посетителя"',new)
        self.assertIn('name="robots" content="index,follow"',new)
        self.assertEqual((backup/"potrebpravo.ru"/"index.html").read_text(encoding="utf-8"),DOC)
        self.assertEqual(prepare(self.plan(),self.parent)[self.root/"index.html"]["new"],new.encode("utf-8"))
    def test_refuses_race_after_preparing_without_any_upload(self):
        edits=prepare(self.plan(),self.parent)
        latest=DOC.replace("Заявка","Изменено в Timeweb после подготовки")
        (self.root/"index.html").write_text(latest,encoding="utf-8")
        with self.assertRaisesRegex(ValueError,"source changed since preflight"):
            apply_edits(edits,self.parent)
        self.assertEqual((self.root/"index.html").read_text(encoding="utf-8"),latest)
        self.assertEqual(len(list(self.parent.glob(".oleg-seo-metadata-backup-*"))),0)
    def test_release_restores_first_file_if_second_replace_fails(self):
        p=self.plan()
        second=self.root/'second.html'
        second.write_text(DOC,encoding='utf-8')
        p['sites'][0]['changes'].append({
            'path':'second.html',
            'expected':{'title':'Старый заголовок','description':'Старое описание страницы'},
            'proposed':{'title':'Другой заголовок','description':'Другое описание'}
        })
        first=self.root/'index.html'
        os.chmod(first,0o640)
        old_mode=first.stat().st_mode & 0o777
        edits=prepare(p,self.parent)
        original_replace=os.replace
        def fail_on_second(src,dst):
            if str(dst)==str(second) and str(src).endswith('.oleg-tmp'):
                raise OSError('simulated mid-release failure')
            return original_replace(src,dst)
        with patch('metadata_guard.os.replace',side_effect=fail_on_second):
            with self.assertRaisesRegex(OSError,'simulated mid-release failure'):
                apply_edits(edits,self.parent)
        self.assertEqual(first.read_text(encoding='utf-8'),DOC)
        self.assertEqual(second.read_text(encoding='utf-8'),DOC)
        self.assertEqual(first.stat().st_mode & 0o777,old_mode)
        self.assertFalse(list(self.root.glob('*.oleg-tmp')))
        self.assertFalse(list(self.root.glob('*.oleg-rollback')))
        backups=list(self.parent.glob('.oleg-seo-metadata-backup-*'))
        self.assertEqual(len(backups),1)
        for name in ['index.html','second.html']:
            self.assertEqual((backups[0]/'potrebpravo.ru'/name).read_text(encoding='utf-8'),DOC)
        receipt=json.loads((backups[0]/'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(len(receipt),2)

    def test_refuses_corrupt_backup_readback_before_modifying_site(self):
        edits=prepare(self.plan(),self.parent)
        original_read=Path.read_bytes
        def corrupted_backup(path):
            data=original_read(path)
            if '.oleg-seo-metadata-backup-' in str(path) and path.name=='index.html':
                return data+b'corrupt'
            return data
        with patch('metadata_guard.Path.read_bytes',autospec=True,side_effect=corrupted_backup):
            with self.assertRaisesRegex(IOError,'backup write verification failed'):
                apply_edits(edits,self.parent)
        self.assertEqual((self.root/'index.html').read_text(encoding='utf-8'),DOC)

    def test_html_escaping_of_title_and_description(self):
        source=DOC
        source=replace_once(source,"title","Старый заголовок",'Заголовок "А & Б"',"sample.html")
        source=replace_once(source,"description","Старое описание страницы",'Кавычки " и амперсанд &',"sample.html")
        self.assertIn('Заголовок &quot;А &amp; Б&quot;',source)
        self.assertIn('Кавычки &quot; и амперсанд &amp;',source)

    def test_refuses_modified_html(self):
        (self.root/"index.html").write_text(DOC.replace("Старый заголовок","Изменён кем-то ещё"),encoding="utf-8")
        with self.assertRaisesRegex(ValueError,"changed since audit"):
            prepare(self.plan(),self.parent)
    def test_refuses_traversal(self):
        p=self.plan();p["sites"][0]["changes"][0]["path"]="../secrets.html"
        with self.assertRaisesRegex(ValueError,"Unsafe relative path"):
            prepare(p,self.parent)
    def test_refuses_duplicate_title(self):
        with self.assertRaisesRegex(ValueError,"exactly one"):
            replace_once(DOC+"<title>Второй</title>","title","Старый заголовок","Новый", "test")
    def test_missing_root_fails_before_write(self):
        p=self.plan();p["sites"].append({"host":"semya-yurist.ru","changes":[{"path":"index.html"}]})
        with self.assertRaises(FileNotFoundError): prepare(p,self.parent)

if __name__=="__main__":
    unittest.main()
