#!/usr/bin/env python3
"""Add two source-grounded, non-fictional legal service pages to private V51 staging only."""
from pathlib import Path
from html import escape
from datetime import date
import json,re,hashlib,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
STAGE=ROOT/'.private-v51-offline'/'candidate'
SPECS={
'potrebpravo.ru':{
 'file':'otkaz-ot-uslug.html','template':'nekachestvennye-uslugi.html',
 'title':'Отказ от договора услуг в Москве — консультация юриста',
 'desc':'Отказ от договора оказания услуг: права потребителя, возврат предоплаты, подтверждение расходов исполнителя, уведомление и документы. Помощь юриста в Москве.',
 'heading':'Отказ от договора услуг и возврат оплаты',
 'lead':'Если услуга больше не нужна или условия договора вызывают вопросы, важно отличить добровольный отказ от спора из-за нарушений исполнителя.',
 'crumb':'Отказ от услуг',
 'sections':[
 ('Когда потребитель может отказаться от услуги',[
 'Статья 32 Закона РФ «О защите прав потребителей» предусматривает возможность отказаться от договора выполнения работ или оказания услуг. При этом потребитель должен оплатить фактически понесённые исполнителем расходы, связанные с исполнением обязательств по этому договору. Результат зависит от характера договора, того, что исполнитель уже сделал, и имеющихся подтверждений.',
 'Правило о праве на отказ не означает автоматического возврата всей внесённой суммы при любых обстоятельствах. Перед предъявлением требования необходимо установить, кто выступает исполнителем, связана ли услуга с личными потребностями, что именно стороны согласовали и какая часть обязательств исполнена.'
 ]),
 ('Добровольный отказ и нарушение договора — разные ситуации',[
 'Когда заказчик просто передумал, обычно необходимо оценивать реально подтверждённые расходы исполнителя. Если же исполнитель нарушил сроки, оказал услугу с недостатками или не выполнил согласованное, возможные требования могут определяться также другими нормами закона. Смешивать эти основания в одной претензии без проверки обстоятельств рискованно.',
 'Важно изучить договор, описание услуги, дату оплаты, переписку, сроки и результат фактического оказания. Стороны могут по-разному понимать объём выполненной работы; документы и хронология помогают определить содержание спора.'
 ]),
 ('Как подготовить уведомление об отказе',[
 'Сохраните договор, заказ, приложение с описанием услуги, чеки, банковские документы и историю общения. Зафиксируйте, какие действия исполнитель успел выполнить на дату уведомления, и какие услуги ещё не оказаны.',
 'В письменном уведомлении укажите стороны и договор, дату отказа, изложите требование о расчёте и возврате соответствующей суммы. Используйте способ отправки, позволяющий подтвердить содержание и получение обращения. Не передавайте в открытых сообщениях избыточные паспортные сведения и пароли.'
 ]),
 ('Какие расходы могут учитываться',[
 'Само по себе указание в договоре на «невозвратную оплату» не заменяет проверку применимого закона. При споре нужно оценить, какие расходы исполнитель понёс именно в связи с исполнением конкретного договора, насколько они документально подтверждены и относятся ли они к спорной услуге.',
 'Если часть услуги уже оказана, сведения об объёме и результате работ также могут иметь значение. Порядок расчёта нельзя надёжно определить только по сумме аванса: требуется анализ документов и фактических обстоятельств.'
 ]),
 ('Если деньги не возвращают',[
 'Для оценки дальнейших действий полезно собрать письменную позицию исполнителя и документы о расходах, которые он предлагает учесть. Юрист может проверить применимость законодательства о защите прав потребителей, требования и доказательства, оценить возможности переговоров и судебной защиты.',
 'Не следует заранее обещать возврат всей оплаты или фиксированную сумму компенсации: такие выводы зависят от договора, нарушений, доказательств и решения суда.'
 ])
 ],
 'faq':[
 ('Можно ли отказаться, если услугу уже начали оказывать?', 'Право на отказ может сохраняться, но фактически понесённые расходы, связанные с договором, могут влиять на итоговый расчёт. Необходимы документы об оказанном объёме и расходах.'),
 ('Достаточно ли написать исполнителю в мессенджере?', 'Важно, чтобы можно было подтвердить содержание заявления, его отправку и получение. Подходящий способ зависит от условий договора и обстоятельств спора.'),
 ('Возвращается ли вся предоплата?', 'Не всегда. Нужно различать отказ без нарушений и отказ вследствие нарушения договора, а также учитывать доказательства исполнения и расходов.'),
 ('Можно ли спорить с удержанием оплаты?', 'Да, при наличии оснований можно поставить вопрос о правомерности и обоснованности удержанных сумм. Для оценки необходимы документы и подтверждения расходов.')
 ],
 'sources':[('Статья 32 Закона о защите прав потребителей','https://www.consultant.ru/document/cons_doc_LAW_305/758e2cfdf136a621c8f66dcb3372b772c7b5e6e8/'),('Обзор практики по отказу потребителя от договора','https://www.consultant.ru/document/cons_doc_LAW_460140/e0449550c512c26e841f7eb5b84b85c51f388883/')],
 'related':[('nekachestvennye-uslugi.html','Некачественные услуги'),('vozvrat-deneg.html','Возврат денег'),('pretenziya-prodavcu.html','Подготовка претензии')]
},
'semya-yurist.ru':{
 'file':'razdel-dolgov.html','template':'razdel-imushchestva.html',
 'title':'Раздел долгов супругов в Москве — кредиты при разводе',
 'desc':'Как разбирают кредиты и долги супругов при разводе: общие и личные обязательства, документы, семейные расходы, ипотека. Консультация семейного юриста в Москве.',
 'heading':'Раздел кредитов и долгов супругов',
 'lead':'После развода спор может касаться не только имущества, но и кредита, займа или других обязательств. Важно установить, для чего возник долг и кто связан договором.',
 'crumb':'Раздел долгов супругов',
 'sections':[
 ('В каких случаях долг считается общим',[
 'В семейном споре наличие кредита у одного супруга само по себе не делает его общим долгом. Значение имеют обстоятельства возникновения обязательства, интересы семьи и использование полученных средств. Статья 45 Семейного кодекса РФ связывает обращение взыскания на общее имущество, в частности, с общими обязательствами либо использованием полученного одним супругом на нужды семьи, если это установлено судом.',
 'При разделе имущества необходимо учитывать и пункт 3 статьи 39 Семейного кодекса РФ: общие долги супругов распределяются между ними пропорционально присуждённым долям. Однако прежде следует установить, что обязательство действительно относится к общим, а не к личным.'
 ]),
 ('Что отличает личный долг от общего',[
 'Необходимо исследовать не только фамилию заёмщика в договоре, но и дату возникновения обязательства, цель займа, документы о расходовании денег, условия кредитования, переписку и фактическое поведение супругов. Долг, оформленный в браке, не всегда связан с потребностями семьи.',
 'Например, при споре о кредите могут иметь значение платежи за семейное жильё, ремонт, совместные покупки и другие подтверждённые расходы. При этом вывод о характере обязательства делается по совокупности доказательств, а не только по заявлению одной стороны.'
 ]),
 ('Раздел долга между супругами и требования банка',[
 'Соглашение супругов о том, кто будет погашать задолженность, не всегда меняет права кредитора по действующему кредитному договору. Следует отдельно выяснить, кто является заёмщиком, созаёмщиком или поручителем, есть ли обеспечение и требуется ли согласие кредитора на изменение обязательства.',
 'Особенно внимательно нужно рассматривать ипотеку: имущественные права на жильё и обязанности по кредиту могут регулироваться разными договорами. Простое распределение долей в квартире не означает автоматической замены стороны в кредитном договоре.'
 ]),
 ('Какие документы нужны для оценки',[
 'Подготовьте кредитные и заёмные договоры, графики платежей, выписки по счетам, сведения о назначении переводов, документы о покупках и ремонте, свидетельство о заключении или расторжении брака, а также относящиеся к спору соглашения.',
 'Если есть ипотека или залог, важны документы на имущество, сведения об обременениях и актуальная информация об остатке долга. Не передавайте открыто пароли от банковских кабинетов, полные реквизиты карт и данные третьих лиц.'
 ]),
 ('Переговоры, соглашение или суд',[
 'Иногда спор можно урегулировать соглашением с оценкой прав и обязанностей каждой стороны. В других случаях требуется судебное определение правового режима активов и обязательств. До выбора способа действий важно проверить интересы детей, условия договоров и возможное участие кредиторов.',
 'Профессиональная оценка начинается с изучения документов, а не с обещания «разделить всё пополам». Результат зависит от конкретных фактов и доказательств.'
 ])
 ],
 'faq':[
 ('Делится ли любой кредит, оформленный в браке?', 'Нет. Нужны основания считать обязательство общим, а не личным. Дата договора сама по себе не решает спор.'),
 ('Если кредит оформлен на одного супруга, он всегда платит один?', 'Не обязательно: значение имеет характер обязательства и доказательства использования средств. При этом отношения с кредитором следует оценивать отдельно.'),
 ('Изменится ли кредитный договор после решения о разделе имущества?', 'Не автоматически. Состав должников и условия договора с кредитором требуют самостоятельной проверки.'),
 ('Можно ли решить вопрос без суда?', 'В ряде ситуаций стороны могут договориться, но необходимо учитывать права кредиторов и предусмотренную законом форму соглашений.')
 ],
 'sources':[('Статья 39 Семейного кодекса РФ','https://www.consultant.ru/document/cons_doc_LAW_8982/4c013b3361ecb92fd4726e329819b847e8378546/'),('Статья 45 Семейного кодекса РФ','https://www.consultant.ru/document/cons_doc_LAW_8982/0ea368c128d5b1aa6845901bacaf6810137469a6/')],
 'related':[('razdel-imushchestva.html','Раздел имущества'),('ipotechnaya-kvartira.html','Ипотечная квартира'),('razvod.html','Расторжение брака')]
}
}
def need_replace(s,pattern,repl,name):
 n=len(re.findall(pattern,s,flags=re.DOTALL))
 if n!=1:raise AssertionError('Expected exactly one '+name+' got '+str(n))
 return re.sub(pattern,lambda _:repl,s,count=1,flags=re.DOTALL)
def content(s,host,sp):
 head='<main class="wrap"><nav class="crumbs" aria-label="Навигационная цепочка"><a href="../index.html">Главная</a> / '+escape(sp['crumb'])+'</nav>'
 head+='<div class="hero"><span class="eyebrow">Москва и Московская область · Юридическая помощь</span><h1>'+escape(sp['heading'])+'</h1><p class="lead">'+escape(sp['lead'])+'</p><span class="tag">Разбор ситуации по документам</span><div class="hero-hotlead" aria-label="Быстрая связь с юристом"><a class="hotlead-call" href="tel:+79172052125">Позвонить и обсудить ситуацию</a><a class="hotlead-more" href="../index.html#contact">Как обратиться</a></div></div>'
 head+='<div class="layout"><div>'
 for title,paragraphs in sp['sections']:
  head+='<section class="paper"><h2>'+escape(title)+'</h2>'
  for paragraph in paragraphs:head+='<p>'+escape(paragraph)+'</p>'
  head+='</section>'
 head+='<section class="paper"><h2>Частые вопросы</h2>'
 for title,answer in sp['faq']:head+='<h3>'+escape(title)+'</h3><p>'+escape(answer)+'</p>'
 head+='<p class="note">Материал носит общий информационный характер и не заменяет индивидуальную консультацию. Для правовой оценки необходимы документы и обстоятельства конкретного дела.</p></section></div>'
 head+='<aside class="aside"><strong>Подготовка к консультации</strong><p>Сохраните документы и опишите ситуацию кратко, не отправляя пароли, полные банковские реквизиты или избыточные персональные данные через открытые сообщения.</p><a href="../index.html#services">Все направления помощи</a><a href="../index.html#team">Специалисты</a><a href="../index.html#contact">Контакты</a></aside></div>'
 head+='<section class="seo-fieldguide" aria-label="Правовые источники"><h2>Нормы закона и дополнительные материалы</h2><p>Информация приведена с учётом действующих положений законодательства Российской Федерации; актуальность редакции следует проверять на момент обращения.</p><ul>'
 for title,url in sp['sources']:head+='<li><a href="'+escape(url,quote=True)+'" target="_blank" rel="noopener noreferrer">'+escape(title)+'</a></li>'
 head+='</ul></section>'
 form='https://b24-s2dosa.bitrix24site.ru/crm_form_fhi3n/' if host=='potrebpravo.ru' else 'https://b24-s2dosa.bitrix24site.ru/crm_form_ep5fd/'
 head+='<section class="cta"><h2>Обсудить ситуацию с юристом</h2><p>Оценка возможных требований начинается с договора и документов. Не гарантируем исход спора без их изучения.</p><p class="oleg-direct-crm-link"><a href="'+form+'" target="_blank" rel="noopener noreferrer">Оставить заявку на консультацию</a></p><p><a href="tel:+79172052125">Позвонить: 8 (917) 205-21-25</a> · <a href="mailto:centr-uprav@inbox.ru">Написать на почту</a></p></section>'
 head+='<h2>Смежные вопросы</h2><nav class="related" aria-label="Другие направления">'
 for href,title in sp['related']:head+='<a href="'+escape(href,quote=True)+'">'+escape(title)+'</a>'
 return head+'</nav></main>'
def make(host,sp):
 root=STAGE/host/'public_html'
 template=root/'services'/sp['template'];target=root/'services'/sp['file']
 if target.exists():raise FileExistsError(target)
 orig=template.read_text()
 s=need_replace(orig,r'<title>.*?</title>','<title>'+escape(sp['title'])+'</title>','title')
 for attr,value in [('description',sp['desc'])]:
  s=need_replace(s,r'<meta name="'+attr+'" content="[^"]*">','<meta name="'+attr+'" content="'+escape(value,quote=True)+'">',attr)
 uri='https://'+host+'/services/'+sp['file']
 s=need_replace(s,r'<link rel="canonical" href="[^"]*">','<link rel="canonical" href="'+uri+'">','canonical')
 for key,val in [('og:title',sp['title']),('og:description',sp['desc']),('og:url',uri)]:
  s=need_replace(s,r'<meta property="'+re.escape(key)+r'" content="[^"]*">','<meta property="'+key+'" content="'+escape(val,quote=True)+'">',key)
 pattern=r'<script type="application/ld\+json">(.*?)</script>'
 match=re.search(pattern,s,flags=re.DOTALL)
 if not match:raise AssertionError('JSON-LD missing')
 obj=json.loads(match.group(1));objs=obj.get('@graph',[]);providers=[x.get('provider') for x in objs if x.get('@type')=='Service']
 if len(providers)!=1:raise AssertionError('Provider not unique')
 label='Защита прав потребителей' if host=='potrebpravo.ru' else 'Семейное право'
 schema={'@context':'https://schema.org','@graph':[
  {'@type':'BreadcrumbList','itemListElement':[{'@type':'ListItem','position':1,'name':label,'item':'https://'+host+'/'},{'@type':'ListItem','position':2,'name':sp['crumb'],'item':uri}]},
  {'@type':'Service','name':sp['heading'],'description':sp['desc'],'url':uri,'serviceType':sp['heading'],'provider':providers[0]}
 ]}
 s=need_replace(s,pattern,'<script type="application/ld+json">'+json.dumps(schema,ensure_ascii=False,separators=(',',':'))+'</script>','JSON-LD')
 s=need_replace(s,r'<main class="wrap">.*?</main>',content(s,host,sp),'main')
 target.write_text(s)
 return uri,hashlib.sha256(s.encode()).hexdigest()
def add_home_link(root,host,sp):
 p=root/'index.html';s=p.read_text()
 needle='<a href="services/'+sp['template']+'">'
 if s.count(needle)!=1:raise AssertionError('Homepage SEO link anchor count '+str(s.count(needle)))
 # Neighbor existing SEO collection, avoids modifying JS-driven service cards.
 snippet='<span style="padding:16px;background:#fff;border:1px solid #d8e3e9;border-radius:12px"><a href="services/'+sp['file']+'">'+escape(sp['crumb'])+'</a></span>'
 at=s.index(needle);insert=s.index('</span>',at)+len('</span>')
 s=s[:insert]+snippet+s[insert:]
 p.write_text(s)
def add_related_link(root,sp):
 p=root/'services'/sp['template'];s=p.read_text()
 a=s.index('<nav class="seo-related"');b=s.index('</nav>',a)
 segment=s[a:b]
 link='<a href="../services/'+sp['file']+'">'+escape(sp['crumb'])+'</a>'
 if link in s:raise AssertionError('Related link duplicate')
 s=s[:b]+link+s[b:];p.write_text(s)
def add_sitemap(root,uri):
 p=root/'sitemap.xml';s=p.read_text();ET.fromstring(s)
 if uri in s:raise AssertionError('Duplicate sitemap URL')
 if s.count('</urlset>')!=1:raise AssertionError('Unexpected Sitemap structure')
 s=s.replace('</urlset>','<url><loc>'+uri+'</loc><lastmod>2026-11-19</lastmod></url></urlset>')
 ET.fromstring(s)
 p.write_text(s)
def main():
 results=[]
 for host,sp in SPECS.items():
  root=STAGE/host/'public_html'
  if not (root/'index.html').exists():raise RuntimeError('Missing prior V51 candidate')
  url,digest=make(host,sp)
  add_home_link(root,host,sp)
  add_related_link(root,sp)
  add_sitemap(root,url)
  results.append({'site':host,'url':url,'sha256':digest,'source_reference_urls':[u for _,u in sp['sources']],'page_bytes':(root/'services'/sp['file']).stat().st_size})
 target=STAGE.parent/'v51_two_legal_pages_manifest.json'
 target.write_text(json.dumps({'scope':'PREPARED OFFLINE — NEVER PUBLISHED','legal_review':'Required before production','pages':results},ensure_ascii=False,indent=2))
 print('V51_ADDED',len(results),'new service pages and home/related/sitemap links')
 print('MANIFEST',str(target))
if __name__=='__main__':main()