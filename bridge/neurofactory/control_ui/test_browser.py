"""Focused local browser smoke; does not call any external APIs."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parent


def run(browser, viewport, name):
    page = browser.new_page(viewport=viewport, device_scale_factor=1)
    failures = []
    page.on('pageerror', lambda error: failures.append(str(error)))
    requests = []
    page.on('request', lambda req: requests.append(req.url))
    html=(ROOT/'index.html').read_text()
    import re
    html=re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', '', html)
    html=re.sub(r'<link rel="stylesheet"[^>]*>', '', html)
    html=re.sub(r'<script defer src="[^"]+"></script>', '', html)
    page.set_content(html)
    page.add_style_tag(content=(ROOT/'styles.css').read_text())
    page.add_script_tag(content=(ROOT/'demo-data.js').read_text())
    page.add_script_tag(content=(ROOT/'app.js').read_text())
    page.get_by_role('heading', name='Центр наблюдения').wait_for()
    assert 'Демонстрационные данные' in page.locator('.warning-strip').inner_text()
    assert 'UNKNOWN' in page.locator('#main-content').inner_text()
    for title, heading in [
        ('Проекты', 'Проекты и направления'),
        ('Очередь заданий', 'Очередь заданий'),
        ('Исполнители', 'Исполнители'),
        ('Ошибки и блокировки','Ошибки и блокировки'),
        ('Контрольные точки','Контрольные точки'),
        ('Независимая проверка','Независимая проверка'),
        ('Карточка задания','Карточка конкретного задания'),
        ('Новый проект','Создание демо-проекта')]:
        page.locator('#navigation button').filter(has_text=title).click()
        page.get_by_role('heading', name=heading, exact=True).wait_for()
    page.locator('#candidate-name').fill('Пробный проект')
    page.locator('#candidate-note').fill('Демо без отправки')
    page.get_by_role('button', name='Сохранить локального кандидата').click()
    assert 'Пробный проект' in page.locator('#main-content').inner_text()
    assert len(requests) == 0, requests  # no network requests at all
    assert not failures, failures
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), 'horizontal overflow'
    page.screenshot(path=str(ROOT / f'screenshot_{name}.png'), full_page=True)
    page.reload()
    assert 'Пробный проект' not in page.content()  # demo candidates not persisted
    page.set_content(html)
    page.add_style_tag(content=(ROOT/'styles.css').read_text())
    page.add_script_tag(content=(ROOT/'demo-data.js').read_text())
    page.add_script_tag(content=(ROOT/'app.js').read_text())
    # Valid import; displays untrusted local label, never verified or live
    page.locator('#file-input').set_input_files(str(ROOT/'demo-bundle.json'))
    page.get_by_role('heading', name='Центр наблюдения').wait_for()
    page.get_by_text('Неподтверждённый локальный снимок', exact=False).wait_for()
    # Valid offline OPS QUEUED claim must import but remain UNKNOWN in UI.
    with TemporaryDirectory() as tmp:
        queued=json.loads((ROOT/'demo-bundle.json').read_text())
        queued['project_detail']['queue'][0]['reported_state']='QUEUED'
        queued['project_detail']['queue'][0]['display_state']='QUEUED'
        candidate=Path(tmp)/'queued.json'
        candidate.write_text(json.dumps(queued),encoding='utf8')
        page.locator('#file-input').set_input_files(str(candidate))
        page.get_by_text('Неподтверждённый локальный снимок', exact=False).wait_for()
        page.locator('#navigation button').filter(has_text='Очередь заданий').click()
        assert 'Заявлено: QUEUED' in page.locator('#main-content').inner_text()
        assert 'UNKNOWN' in page.locator('#main-content').inner_text()
        page.locator('#navigation button').filter(has_text='Главная панель').click()
    # Forged permissions, duplicate keys, and HTML payload must not be accepted
    with TemporaryDirectory() as temp:
        tmp=Path(temp)
        bad=json.loads((ROOT/'demo-bundle.json').read_text())
        bad['actions_allowed']['publish']=True
        forged=tmp/'forged.json';forged.write_text(json.dumps(bad),encoding='utf8')
        page.locator('#file-input').set_input_files(str(forged))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')")
        bad=json.loads((ROOT/'demo-bundle.json').read_text())
        bad['project_detail']['problems'][0]['code']='APPROVE'
        incident=tmp/'incident.json';incident.write_text(json.dumps(bad),encoding='utf8')
        page.locator('#file-input').set_input_files(str(incident))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')")
        duplicate=tmp/'duplicate.json';duplicate.write_text('{"schema":1,"schema":1}',encoding='utf8')
        page.locator('#file-input').set_input_files(str(duplicate))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')")
        bad=json.loads((ROOT/'demo-bundle.json').read_text())
        bad['project_detail']['problems'][0]['code']='<img src=x onerror=alert(1)>'
        injected=tmp/'injected.json';injected.write_text(json.dumps(bad),encoding='utf8')
        page.locator('#file-input').set_input_files(str(injected))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')") or page.locator('img').count()==0
    page.locator('#reset-btn').click()
    assert 'Демонстрационные данные' in page.locator('.warning-strip').inner_text()
    page.close()
    return len(requests)

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path='/usr/bin/chromium', args=['--no-sandbox','--no-proxy-server','--proxy-bypass-list=*'])
    for name,viewport in [('desktop',{'width':1440,'height':900}),('iphone',{'width':390,'height':844})]:
        requests=run(browser,viewport,name)
        print(name, 'PASS', 'local resource loads:', requests, 'screenshot:', ROOT / f'screenshot_{name}.png')
    browser.close()
