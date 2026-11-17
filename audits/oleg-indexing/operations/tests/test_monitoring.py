"""Offline regression for Oleg public health checks and private-site backups."""
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
health=load("olegh","check_live_sites.py")
backup=load("olegb","backup_timeweb.py")
def sample(site):
    form=health.SITES[site]["form"]
    page=('<html lang="ru"><head><title>Юрист Москва</title>'
          '<meta name="description" content="Обратитесь к юристу">'
          '<link rel="canonical" href="https://'+site+'/">'
          '<script type="application/ld+json">{}</script>'
          '</head><body>'
          '<a href="https://'+health.FORM_HOST+'/'+form+'/">Битрикс</a>'
          '<a href="tel:+79172052125">Звонок</a>'
          '<a href="mailto:centr-uprav@inbox.ru">Почта</a>'
          '<script src="/assets/oleg-analytics-v1.js"></script>'
          '</body></html>').encode()
    xml=('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
         '<url><loc>https://'+site+'/</loc></url></urlset>').encode()
    return page,xml
def mock(host,*,remove_tel=False,foreign_url=False):
    page,sitemap=sample(host)
    if remove_tel:page=page.replace(b"tel:+79172052125",b"tel:+000")
    if foreign_url:sitemap=sitemap.replace(host.encode(),b"evil.example")
    def get(url):
        p=url.split(host,1)[-1]
        if p=="/":return 200,page,"https://"+host+"/"
        if p=="/robots.txt":return 200,("User-agent: *\nAllow: /\nSitemap: https://"+host+"/sitemap.xml\n").encode(),"https://"+host+p
        if p=="/sitemap.xml":return 200,sitemap,"https://"+host+p
        raise ValueError("unexpected URL")
    return get
class MonitorTests(unittest.TestCase):
    def test_valid_home_and_sitemap(self):
        h="potrebpravo.ru"
        cfg={**health.SITES[h],"min_sitemap":1}
        r=health.check_site(h,cfg,mock(h),all_pages=False)
        self.assertTrue(r["ok"],r)
        self.assertFalse(r["external_form_dom_checked"])
    def test_broken_phone_detected(self):
        h="potrebpravo.ru"
        cfg={**health.SITES[h],"min_sitemap":1}
        r=health.check_site(h,cfg,mock(h,remove_tel=True),all_pages=False)
        self.assertIn("homepage_telephone",r["errors"])
    def test_noindex_detected(self):
        h="semya-yurist.ru"
        cfg={**health.SITES[h],"min_sitemap":1}
        source=mock(h)
        def get(url):
            code,data,final=source(url)
            if url.endswith("/"):
                data=data.replace(b"</head>",b'<meta name="robots" content="noindex"></head>')
            return code,data,final
        self.assertIn("homepage_indexable",health.check_site(h,cfg,get,all_pages=False)["errors"])
    def test_foreign_sitemap_rejected(self):
        with self.assertRaisesRegex(ValueError,"foreign"):
            health.sitemap_pages("potrebpravo.ru",sample("potrebpravo.ru")[1].replace(b"potrebpravo.ru",b"evil.example"))
    def test_xml_entity_rejected(self):
        with self.assertRaisesRegex(ValueError,"unsafe"):
            health.sitemap_pages("potrebpravo.ru",b'<!DOCTYPE urlset [<!ENTITY x SYSTEM "file:///etc/passwd">]><urlset/>')
    def test_public_200_never_called_crm_delivery(self):
        h="potrebpravo.ru"
        result=health.check_site(h,{**health.SITES[h],"min_sitemap":1},mock(h),all_pages=False)
        self.assertNotIn("crm_delivery_verified",result)
        self.assertFalse(result["external_form_dom_checked"])
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="oleg-auto-backup-test.")
        self.home=Path(self.temp.name)
        self.b=load("olegb_test","backup_timeweb.py")
        self.b.HOME=self.home
        self.b.BACKUPS=self.home/".oleg-safe-backups"/"oleg-managed-daily"
        for h in self.b.SITES:
            p=self.home/h/"public_html"
            p.mkdir(parents=True)
            for i in range(60):
                (p/f"page{i:03d}.html").write_text("<html>synthetic only</html>")
    def tearDown(self):self.temp.cleanup()
    def test_backup_creation_and_hash(self):
        self.b.main()
        metas=list(self.b.BACKUPS.glob("*.json"))
        self.assertEqual(len(metas),1)
        meta=json.loads(metas[0].read_text())
        self.assertEqual(meta["files"],120)
        archive=self.b.BACKUPS/meta["archive"]
        self.assertTrue(archive.is_file())
        self.assertEqual(self.b.sha(archive),meta["sha256"])
        self.assertEqual(archive.stat().st_mode & 0o777,0o600)
        self.assertEqual(metas[0].stat().st_mode & 0o777,0o600)
    def test_no_overwrite_backup(self):
        self.b.main();self.b.main()
        self.assertEqual(len(list(self.b.BACKUPS.glob("*.json"))),2)
    def test_missing_live_site_aborts(self):
        for p in (self.home/"semya-yurist.ru"/"public_html").glob("*.html"):p.unlink()
        with self.assertRaisesRegex(RuntimeError,"missing"):
            self.b.main()
    def test_symlink_in_site_rejected(self):
        p=self.home/"potrebpravo.ru"/"public_html"/"test-link"
        p.symlink_to("/etc/hosts")
        with self.assertRaisesRegex(RuntimeError,"unsupported"):
            self.b.main()
if __name__=="__main__":unittest.main(verbosity=2)
