#!/usr/bin/env python3
"""Update staged sitemap lastmod only for V51 meaningfully edited landing pages."""
from pathlib import Path
from xml.etree import ElementTree as ET
import json,re
ROOT=Path(__file__).resolve().parents[2]
STAGE=ROOT/'.private-v51-offline'/'candidate'
PAGES={
 'potrebpravo.ru':['/','/services/nekachestvennye-uslugi.html','/services/neustoyka-zastroishchika.html','/services/pretenziya-prodavcu.html','/services/strahovye-spory.html','/services/vozvrat-avtomobilya.html','/services/vozvrat-deneg.html'],
 'semya-yurist.ru':['/','/services/alimenty.html','/services/brachnyi-dogovor.html','/services/ipotechnaya-kvartira.html','/services/razdel-imushchestva.html','/services/razvod.html','/services/spory-o-detyakh.html']
}
def main():
 count=0
 for host,paths in PAGES.items():
  p=STAGE/host/'public_html'/'sitemap.xml'
  original=p.read_text()
  changed=original
  for path in paths:
   url='https://'+host+path
   pattern=r'(<loc>'+re.escape(url)+r'</loc><lastmod>)\d{4}-\d{2}-\d{2}(</lastmod>)'
   changed,n=re.subn(pattern,r'\g<1>2026-11-19\g<2>',changed)
   if n!=1:raise AssertionError('Sitemap URL/lastmod not unique: '+url)
   count+=n
  root=ET.fromstring(changed)
  dates={n.find('{*}loc').text:n.find('{*}lastmod').text for n in root.findall('{*}url')}
  for path in paths:
   if dates['https://'+host+path]!='2026-11-19':raise AssertionError('Timestamp not persisted')
  if count!=len(PAGES['potrebpravo.ru'])+len(PAGES['semya-yurist.ru']) and host=='semya-yurist.ru':raise AssertionError('Incomplete update')
  p.write_text(changed)
 print('V51_SITEMAP_LASTMOD_UPDATED',count,'staged HTML URLs; no production')
if __name__=='__main__':main()