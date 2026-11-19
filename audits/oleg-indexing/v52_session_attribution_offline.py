#!/usr/bin/env python3
"""V52: consented, 30-minute session attribution for Bitrix CRM forms; offline-only."""
from pathlib import Path
import shutil,hashlib,re,json
ROOT=Path(__file__).resolve().parents[2]
V51=ROOT/'.private-v51-offline'/'candidate'
V52=ROOT/'.private-v52-offline'/'candidate'
MANIFEST=ROOT/'.private-v52-offline'/'v52-attribution-manifest.json'
HOSTS=('potrebpravo.ru','semya-yurist.ru')
CAMPAIGN_KEY='oleg.campaign.v52'
BASE_SHA={}
def sha(s):return hashlib.sha256(s.encode('utf-8')).hexdigest()
def build():
 if V52.exists():raise FileExistsError('V52 already present: refuse overwrite')
 V52.parent.mkdir(parents=True,exist_ok=True)
 shutil.copytree(V51,V52)
 result=[]
 for host in HOSTS:
  base=V52/host/'public_html'
  analytics=base/'assets'/'oleg-analytics-v1.js'
  assistant=base/'assets'/'legal-assistant-v4.js'
  a=analytics.read_text();b=assistant.read_text()
  # First-party campaign parameters are captured in sessionStorage only once tracking consent is granted.
  needle="""    if (yclid && /^\\d{1,30}$/.test(yclid)) campaign.set('yclid', yclid);
    const pageUrl = location.origin"""
  replace="""    if (yclid && /^\\d{1,30}$/.test(yclid)) campaign.set('yclid', yclid);
    // Only after consent: keep non-personal campaign tags across internal pages.
    // A fresh tagged visit replaces the previous 30-minute session attribution.
    try {
      if (campaign.size) sessionStorage.setItem('oleg.campaign.v52', JSON.stringify({
        at: Date.now(), params: Object.fromEntries(campaign.entries())
      }));
    } catch (_) {}
    const pageUrl = location.origin"""
  if a.count(needle)!=1:raise ValueError('Analytics consented capture anchor changed: '+host)
  a=a.replace(needle,replace,1)
  old="""      var source = new URLSearchParams(location.search || '');
      for (var key of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
        var value = source.get(key);
        if (value && /^[\\p{L}\\p{N}_ .:+|{}~-]{1,180}$/u.test(value)) dest.searchParams.set(key, value);
      }
      anchor.href = dest.toString();"""
  new="""      var source = new URLSearchParams(location.search || '');
      var saved = {};
      if (consentGranted()) {
        try {
          var payload = JSON.parse(sessionStorage.getItem('oleg.campaign.v52') || 'null');
          if (payload && Date.now() - payload.at >= 0 && Date.now() - payload.at < 1800000) saved = payload.params || {};
        } catch (_) {}
      }
      for (var key of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
        var value = source.get(key) || saved[key];
        if (value && /^[\\p{L}\\p{N}_ .:+|{}~-]{1,180}$/u.test(value)) dest.searchParams.set(key, value);
      }
      var yclid = source.get('yclid') || saved.yclid;
      if (yclid && /^\\d{1,30}$/.test(yclid)) dest.searchParams.set('yclid', yclid);
      anchor.href = dest.toString();"""
  if a.count(old)!=1:raise ValueError('Direct link anchor changed: '+host)
  a=a.replace(old,new,1)
  orig_b="""    const query = new URLSearchParams(location.search || '');
    for (const key of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
      const v = query.get(key);
      if (v && /^[\\p{L}\\p{N}_ .:+|{}~-]{1,180}$/u.test(v)) link.searchParams.set(key, v);
    }
    return link.toString();"""
  next_b="""    const query = new URLSearchParams(location.search || '');
    let saved = {};
    try {
      const consent = JSON.parse(localStorage.getItem('oleg.analytics.choice.v1') || 'null');
      if (consent?.value === 'yes' && window.__olegAnalyticsStarted === true) {
        const payload = JSON.parse(sessionStorage.getItem('oleg.campaign.v52') || 'null');
        if (payload && Date.now() - payload.at >= 0 && Date.now() - payload.at < 1800000) saved = payload.params || {};
      }
    } catch (_) {}
    for (const key of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
      const v = query.get(key) || saved[key];
      if (v && /^[\\p{L}\\p{N}_ .:+|{}~-]{1,180}$/u.test(v)) link.searchParams.set(key, v);
    }
    const yclid = query.get('yclid') || saved.yclid;
    if (yclid && /^\\d{1,30}$/.test(yclid)) link.searchParams.set('yclid', yclid);
    return link.toString();"""
  if b.count(orig_b)!=1:raise ValueError('Assistant form anchor changed: '+host)
  b=b.replace(orig_b,next_b,1)
  if 'oleg_lead_success' not in a:raise AssertionError('False-goal guard missing')
  analytics.write_text(a);assistant.write_text(b)
  av=sha(a)[:8];bv=sha(b)[:8]
  count_a=count_b=0
  for page in base.rglob('*.html'):
   s=page.read_text()
   s1,n=re.subn(r'(/assets/oleg-analytics-v1\.js\?v=)[0-9a-f]{8}',lambda m:m.group(1)+av,s)
   s2,n2=re.subn(r'(/assets/legal-assistant-v4\.js\?v=)[0-9a-f]{8}',lambda m:m.group(1)+bv,s1)
   if n or n2:page.write_text(s2)
   count_a+=n;count_b+=n2
  # URLs in new V51 pages always require the fresh V52 JS cache version.
  if count_a<15 or count_b<15:raise AssertionError('Too few cache-bust HTML refs on '+host+': '+str((count_a,count_b)))
  result.append({'host':host,'analytics_sha256':sha(a),'assistant_sha256':sha(b),
                 'analytics_cache':av,'assistant_cache':bv,'analytics_refs_updated':count_a,'assistant_refs_updated':count_b})
 MANIFEST.write_text(json.dumps({'status':'STAGED_V52_ONLY_NOT_PRODUCTION','campaign_session_ttl_seconds':1800,
            'storage_only_after_consent':True,'sites':result},ensure_ascii=False,indent=2))
 print('V52_ATTRIBUTION_STAGE_READY',json.dumps(result,ensure_ascii=False))
if __name__=='__main__':build()