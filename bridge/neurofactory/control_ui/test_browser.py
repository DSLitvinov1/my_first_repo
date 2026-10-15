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
        queued['project_detail']['queue'][0]['display_state']='UNKNOWN'
        queued['project_detail']['queue'][0]['checkpoint']['reported_state']='MISSING'
        queued['project_detail']['checkpoint_counts']={'MISSING':1}
        queued['project_detail']['stopped_tasks']=[]
        queued['project_detail']['problems']=[]
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
    # New negative regressions: previously accepted these four forged structures.
    with TemporaryDirectory() as temp:
        checks=[]
        forged=json.loads((ROOT/'demo-bundle.json').read_text())
        forged['project_detail']['queue'][0]['reported_state']='APPROVE'
        checks.append(('forged-task-state',forged))
        forged=json.loads((ROOT/'demo-bundle.json').read_text())
        lane=next(x for x in forged['board']['lanes'] if x['lane']=='OPS')
        lane['commit']=None;lane['issue_url']=None;lane['source']=None
        forged['consistency']={'board_project_match':None,'status':'SOURCE_MISSING','does_not_attest_provenance':True}
        checks.append(('missing-lane-provenance',forged))
        forged=json.loads((ROOT/'demo-bundle.json').read_text())
        forged['coordinator_task_card']['task_id']=None
        forged['coordinator_task_card']['reported_phase']='unknown'
        checks.append(('absent-card-with-sha',forged))
        forged=json.loads((ROOT/'demo-bundle.json').read_text())
        forged['project_detail']['last_reported_success']={
          'id':9,'state':'COMPLETED','conclusion':'APPROVE',
          'head_sha':'a'*40,'matches_project_head':True,
          'url':'https://github.com/evil/repo','source_verified':False}
        checks.append(('forged-run-conclusion',forged))
        forged=json.loads((ROOT/'demo-bundle.json').read_text())
        forged['consistency']['status']='DECLARATIONS_DIFFER'
        checks.append(('forged-consistency',forged))
        for label, payload in checks:
            path=Path(temp)/(label+'.json')
            path.write_text(json.dumps(payload),encoding='utf8')
            page.locator('#toast').evaluate('(el) => { el.hidden = true; el.textContent = ""; }')
            page.locator('#file-input').set_input_files(str(path))
            page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')",timeout=3500)
            assert 'Неподтверждённый локальный снимок' in page.locator('.warning-strip').inner_text(),label
    # Narrow source-contract regressions: reject forged metadata that used to pass.
    with TemporaryDirectory() as temp:
        source=json.loads((ROOT/'demo-bundle.json').read_text())
        def check_bad(label, transform):
            packet=json.loads(json.dumps(source))
            transform(packet)
            path=Path(temp)/(label+'.json')
            path.write_text(json.dumps(packet),encoding='utf8')
            page.locator('#toast').evaluate('(el) => {el.hidden=true;el.textContent="";}')
            page.locator('#file-input').set_input_files(str(path))
            page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')",timeout=3500)
            assert 'Неподтверждённый локальный снимок' in page.locator('.warning-strip').inner_text(),label
        check_bad('forged-worker',lambda x:x['project_detail']['workers'].append({'id':'WIN-X','role':'worker','reported_state':'APPROVE','display_state':'UNKNOWN','seconds_since_reported_heartbeat':None}))
        check_bad('duplicate-task',lambda x:x['project_detail']['queue'].append(dict(x['project_detail']['queue'][0])))
        check_bad('forged-checkpoints',lambda x:x['project_detail'].__setitem__('checkpoint_counts',{'VERIFIED':999}))
        check_bad('forged-severity',lambda x:x['project_detail']['problems'][0].__setitem__('severity','WARNING'))
        check_bad('forged-stalled',lambda x:x['project_detail'].__setitem__('possibly_stalled_tasks',['GHOST']))
    # Regression: missing project source must not carry phantom queue or results;
    # last reported run must agree with the success/failure highlights.
    with TemporaryDirectory() as tmp:
        original=json.loads((ROOT/'demo-bundle.json').read_text())
        hostile=[]
        p=json.loads(json.dumps(original))
        p['project_detail']['project']=None
        p['project_detail']['observed_at']=None
        p['consistency']={'board_project_match':None,'status':'SOURCE_MISSING','does_not_attest_provenance':True}
        hostile.append(('missing-project-with-queue',p))
        p=json.loads(json.dumps(original))
        src=p['project_detail']['project']
        run={'id':100,'state':'COMPLETED','conclusion':'SUCCESS',
             'head_sha':src['head_sha'],'matches_project_head':True,
             'url':f"https://github.com/{src['repository']}/actions/runs/100",
             'source_verified':False}
        p['project_detail']['last_reported_success']=run
        p['project_detail']['last_reported_run']={**run,'id':99,'state':'IN_PROGRESS',
                'conclusion':'UNKNOWN','url':run['url'].replace('/100','/99')}
        hostile.append(('inconsistent-run-order',p))
        p=json.loads(json.dumps(original))
        p['project_detail']['bridge']['seconds_since_reported_heartbeat']={'forged':'age'}
        hostile.append(('invalid-bridge-age',p))
        for name,packet in hostile:
            path=Path(tmp)/(name+'.json')
            path.write_text(json.dumps(packet),encoding='utf-8')
            page.locator('#toast').evaluate('(el) => {el.hidden=true;el.textContent="";}')
            page.locator('#file-input').set_input_files(str(path))
            page.wait_for_function("document.querySelector('#toast').textContent.includes('Файл отклонён')",timeout=3500)
            assert 'Неподтверждённый локальный снимок' in page.locator('.warning-strip').inner_text(),name
        # A legitimate coordinator-board-only payload has no OPS project or fabricated queue.
        board_only=json.loads(json.dumps(original))
        board_only['project_detail']={
            'project':None,'source_verified':False,'observed_at':None,
            'bridge':{'reported_state':'UNKNOWN','display_state':'UNKNOWN','seconds_since_reported_heartbeat':None},
            'workers':[],'queue':[],'checkpoint_counts':{},'problems':[],
            'stopped_tasks':[],'possibly_stalled_tasks':[],
            'last_reported_success':None,'last_reported_failure':None,'last_reported_run':None,
            'last_run_sort':'HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED'
        }
        board_only['consistency']={'board_project_match':None,'status':'SOURCE_MISSING','does_not_attest_provenance':True}
        path=Path(tmp)/'board-only.json'
        path.write_text(json.dumps(board_only),encoding='utf-8')
        page.locator('#toast').evaluate('(el) => {el.hidden=true;el.textContent="";}')
        page.locator('#file-input').set_input_files(str(path))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('снимок принят')",timeout=3500)
        assert 'Неподтверждённый локальный снимок' in page.locator('.warning-strip').inner_text()
    # Card navigation regression: independent coordinator card survives absent OPS queue,
    # and clicking the second OPS task must select THAT task, not the first.
    with TemporaryDirectory() as temp:
        original=json.loads((ROOT/'demo-bundle.json').read_text())
        board=json.loads(json.dumps(original))
        board['project_detail']={
            'project':None,'source_verified':False,'observed_at':None,
            'bridge':{'reported_state':'UNKNOWN','display_state':'UNKNOWN','seconds_since_reported_heartbeat':None},
            'workers':[],'queue':[],'checkpoint_counts':{},'problems':[],
            'stopped_tasks':[],'possibly_stalled_tasks':[],
            'last_reported_success':None,'last_reported_failure':None,'last_reported_run':None,
            'last_run_sort':'HIGHEST_REPORTED_RUN_ID_NOT_GITHUB_ATTESTED'
        }
        board['consistency']={'board_project_match':None,'status':'SOURCE_MISSING','does_not_attest_provenance':True}
        path=Path(temp)/'coordinator-only.json'
        path.write_text(json.dumps(board),encoding='utf8')
        page.locator('#toast').evaluate('(e)=> {e.hidden=true;e.textContent=""}')
        page.locator('#file-input').set_input_files(str(path))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('снимок принят')",timeout=3500)
        page.locator('#navigation button').filter(has_text='Карточка задания').click()
        assert page.get_by_text('Отдельная карточка координатора',exact=True).count()==1
        assert 'NF-DEV-05-Q091' in page.locator('#main-content').inner_text()
        assert 'Нет данных OPS о задании' in page.locator('#main-content').inner_text()
        two=json.loads(json.dumps(original))
        second=json.loads(json.dumps(two['project_detail']['queue'][0]))
        second['task_id']='NF-DEV-05-Q092'
        two['project_detail']['queue'].append(second)
        two['project_detail']['checkpoint_counts']['PARTIAL']=2
        two['project_detail']['stopped_tasks'].append(second['task_id'])
        path=Path(temp)/'two-tasks.json'
        path.write_text(json.dumps(two),encoding='utf8')
        page.locator('#toast').evaluate('(e)=> {e.hidden=true;e.textContent=""}')
        page.locator('#file-input').set_input_files(str(path))
        page.wait_for_function("document.querySelector('#toast').textContent.includes('снимок принят')",timeout=3500)
        page.locator('#navigation button').filter(has_text='Очередь заданий').click()
        choices=page.locator('#main-content .item-row button').filter(has_text='Карточка')
        assert choices.count()==2
        choices.nth(1).click()
        first_card=page.locator('#main-content .card').first.inner_text()
        assert 'NF-DEV-05-Q092' in first_card and 'NF-DEV-05-Q091' not in first_card
        assert page.get_by_text('Отдельная карточка координатора',exact=True).count()==1
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
