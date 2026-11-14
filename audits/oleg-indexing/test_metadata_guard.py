import json
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
