"""Public synthetic CRM: Qwen plans and writes all modules from a Russian brief."""
import ast,hashlib,json,os,pathlib,subprocess,sys,time,urllib.request
ROOT=pathlib.Path(os.getenv("RUNNER_TEMP","/tmp"))/"nf_ru_crm"
WRITER="qwen2.5-coder:3b"; REVIEWER="qwen3:4b"
MODULES=("storage.py","crm.py","main.py")
FILES=MODULES+("test_crm.py","README.md")
URL="http://127.0.0.1:11434/api/generate"
BRIEF=("Сделай с нуля мини-CRM на Python для вымышленных заявок. Добавление "
"заявки (имя клиента и заметка), редактирование, статусы new/in_progress/done, "
"поиск по имени или заметке без учёта регистра, сохранение JSON и загрузка. "
"Каждая заявка имеет уникальный целый id. Только стандартная библиотека, без сети. "
"storage.py: load_records(path)->list (пустой список, если нет файла), "
"save_records(path,records)->None. "
"crm.py: add_record(records,customer,note)->dict; "
"update_record(records,id,customer=None,note=None)->dict; "
"set_status(records,id,status)->dict (неизвестный статус вызывает ValueError); "
"search_records(records,text)->list. Неизвестный id вызывает LookupError. "
"main.py: python main.py --db ПУТЬ add ИМЯ ЗАМЕТКА / list / search СЛОВО / "
"edit ID ИМЯ ЗАМЕТКА / status ID СТАТУС. Каждый вызов печатает только JSON. "
"Команды add/edit/status сохраняют JSON-файл. "
"Самостоятельно разработай всё содержимое трёх модулей.")
TEST=r'''import unittest,tempfile,subprocess,sys,json
from pathlib import Path
import crm,storage
class TestCRM(unittest.TestCase):
 def setUp(self):
  self.rows=[]
  self.tmp=tempfile.TemporaryDirectory()
  self.addCleanup(self.tmp.cleanup)
  self.db=str(Path(self.tmp.name)/"requests.json")
 def add(self):return crm.add_record(self.rows,"Олег","Перезвонить")
 def cli(self,*args):
  p=subprocess.run([sys.executable,"-S","main.py","--db",self.db,*map(str,args)],capture_output=True,text=True,timeout=8)
  if p.returncode:raise AssertionError(p.stderr[-300:])
  return json.loads(p.stdout)
 def test_new(self):self.assertEqual(self.add()["status"],"new")
 def test_append(self):self.add();self.assertEqual(len(self.rows),1)
 def test_ids(self):self.assertNotEqual(self.add()["id"],self.add()["id"])
 def test_edit_customer(self):
  x=self.add();crm.update_record(self.rows,x["id"],customer="Ирина");self.assertEqual(x["customer"],"Ирина")
 def test_edit_note(self):
  x=self.add();crm.update_record(self.rows,x["id"],note="Готово");self.assertEqual(x["note"],"Готово")
 def test_status(self):
  x=self.add();crm.set_status(self.rows,x["id"],"done");self.assertEqual(x["status"],"done")
 def test_bad_status(self):
  x=self.add()
  with self.assertRaises(ValueError):crm.set_status(self.rows,x["id"],"deleted")
 def test_missing(self):
  with self.assertRaises(LookupError):crm.update_record(self.rows,555,customer="Нет")
 def test_search_name(self):self.add();self.assertEqual(len(crm.search_records(self.rows,"ОЛЕГ")),1)
 def test_search_note(self):self.add();self.assertEqual(len(crm.search_records(self.rows,"перезвонить")),1)
 def test_search_absent(self):self.assertEqual(crm.search_records(self.rows,"ничего"),[])
 def test_missing_file(self):self.assertEqual(storage.load_records(self.db),[])
 def test_save_load(self):
  self.add();storage.save_records(self.db,self.rows);self.assertEqual(len(storage.load_records(self.db)),1)
 def test_cli_add_list(self):
  x=self.cli("add","Тест","Заявка");self.assertEqual(x["status"],"new");self.assertEqual(len(self.cli("list")),1)
 def test_cli_edit_search(self):
  x=self.cli("add","Тест","Заявка");self.cli("edit",x["id"],"Мария","Новая")
  self.assertEqual(self.cli("search","мария")[0]["note"],"Новая")
 def test_cli_status(self):
  x=self.cli("add","Тест","Заявка");self.cli("status",x["id"],"done")
  self.assertEqual(self.cli("list")[0]["status"],"done")
if __name__=="__main__":unittest.main(verbosity=2)
'''
def safe(n):
 if n not in FILES+("architecture-plan.json","verification-manifest.json"):
  raise ValueError("Unexpected file")
 ROOT.mkdir(parents=True,exist_ok=True);p=ROOT/n
 if p.is_symlink() or ROOT.is_symlink() or p.resolve().parent!=ROOT.resolve():
  raise ValueError("Unsafe file")
 return p
def generate(model,prompt,limit=1550,structured=False):
 body={"model":model,"prompt":prompt,"think":False,"stream":False,"keep_alive":"0",
       "options":{"num_ctx":3072,"num_predict":limit,"num_gpu":0,"num_thread":3,"temperature":0}}
 if structured:body["format"]="json"
 req=urllib.request.Request(URL,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=280) as response:
  j=json.load(response)
 if not j.get("done"):raise ValueError("Incomplete model answer")
 return j.get("response","")
def strip_code(raw):
 s=raw.strip()
 if s.startswith(chr(96)*3):
  lines=s.splitlines()
  s="\n".join(lines[1:-1])
 return s.strip()+"\n"
def validate_source(code,name):
 t=ast.parse(code)
 if len(code)>14000 or len(list(ast.walk(t)))>900:raise ValueError("Oversized source")
 allowed={"json","argparse","sys","pathlib","typing","crm","storage"}
 for n in ast.walk(t):
  if isinstance(n,ast.Import) and any(a.name.split(".")[0] not in allowed for a in n.names):
   raise ValueError("Disallowed import")
  if isinstance(n,ast.ImportFrom) and str(n.module).split(".")[0] not in allowed:
   raise ValueError("Disallowed from import")
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in ("eval","exec","compile","__import__","input"):
   raise ValueError("Unsafe builtin call")
 if name=="main.py" and "argparse" not in code:raise ValueError("No CLI")
def test():
 e={k:v for k,v in os.environ.items() if k in ("PATH","HOME","LANG","TMPDIR")}
 p=subprocess.run([sys.executable,"-S","test_crm.py"],cwd=ROOT,env=e,capture_output=True,text=True,timeout=130)
 if p.returncode:raise ValueError((p.stderr+p.stdout)[-3000:])
 return {"passed":16,"total":16}
def run():
 if os.getenv("NEUROFACTORY_PUBLIC_FREE_RUN_CONFIRMED")!="yes" or os.getenv("GITHUB_REPOSITORY")!="DSLitvinov1/my_first_repo":
  raise ValueError("Only synthetic free public cloud")
 start=time.monotonic()
 prompt=("Ты архитектор ИИ. По русскому ТЗ самостоятельно составь план. Верни только JSON "
 "с ключами architecture (строка), files (ровно три объекта с name и responsibility) "
 "и milestones (массив). Файлы storage.py, crm.py, main.py. Без кода. ТЗ: "+BRIEF)
 plan=json.loads(generate(WRITER,prompt,780,True))
 if {v["name"] for v in plan["files"]}!=set(MODULES):raise ValueError("Planning failed")
 safe("architecture-plan.json").write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding="utf-8")
 modules={}
 for file in MODULES:
  role=next(v["responsibility"] for v in plan["files"] if v["name"]==file)
  prompt=("Ты программист ИИ. Напиши ПОЛНЫЙ файл "+file+" самостоятельно, "
          "без готовых шаблонов. Верни только исходный код Python без пояснений. "
          "ТЗ: "+BRIEF+"\nПЛАН: "+str(plan["architecture"])+
          "\nТвоя роль: "+role+"\nУже созданные файлы: "+json.dumps(modules,ensure_ascii=False))
  code=strip_code(generate(WRITER,prompt,1750))
  validate_source(code,file)
  safe(file).write_text(code,encoding="utf-8")
  modules[file]=code
  print("AI created",file,len(code),flush=True)
 safe("test_crm.py").write_text(TEST,encoding="utf-8")
 safe("README.md").write_text("Educational CRM. All three app modules generated by Qwen from Russian brief. "
 "Test suite independently authored; fake data only.\n",encoding="utf-8")
 repaired=0
 for attempt in range(3):
  try:result=test();break
  except Exception as e:
   print("TEST FAILURE",attempt+1,str(e)[-650:],flush=True)
   if attempt==2:raise
   repaired+=1
   for file in MODULES:
    p=("Исправь ПОЛНЫЙ файл "+file+". Не меняй тесты и API. Верни только Python. "
       "ТЗ: "+BRIEF+"\nОшибки тестов: "+str(e)[-2200:]+
       "\nТекущий код: "+modules[file]+
       "\nДругие файлы: "+json.dumps({k:v for k,v in modules.items() if k!=file},ensure_ascii=False))
    response=strip_code(generate(WRITER,p,1750))
    try:validate_source(response,file)
    except (ValueError,SyntaxError):continue
    modules[file]=response;safe(file).write_text(response,encoding="utf-8")
 review=("Ты независимый ИИ-ревьюер. Проверь все три созданных файла на соответствие ТЗ "
         "мини-CRM. Добавление, статусы, редактирование, поиск и сохранение. "
         "16 независимых тестов пройдены. Ответ только JSON с verdict REVIEW_OK или REVIEW_BAD "
         "и reason. ТЗ: "+BRIEF+"\n"+
         "\n".join(k+"\n"+modules[k] for k in MODULES))
 raw=generate(REVIEWER,review,430,True)
 print("REVIEW JSON",repr(raw[:400]),flush=True)
 parsed=json.loads(raw)
 if parsed.get("verdict")!="REVIEW_OK":raise ValueError("Independent review failed")
 manifest={"status":"two_models_reviewed","writer":WRITER,"reviewer":{"model":REVIEWER,"verdict":"REVIEW_OK"},
  "app_modules":list(MODULES),"architecture":plan,"tests":result,"repair_rounds":repaired,
  "hashes":{f:hashlib.sha256(safe(f).read_bytes()).hexdigest() for f in FILES},
  "seconds":round(time.monotonic()-start,1)}
 for n in MODULES:validate_source(safe(n).read_text(encoding="utf-8"),n)
 test()
 safe("verification-manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
 print(json.dumps({"status":"success","tests":16,"reviewer":REVIEWER,"repairs":repaired,"seconds":manifest["seconds"]}))
if __name__=="__main__":
 try:run()
 except Exception as e:
  print("CRM SAFE STOP",type(e).__name__,str(e)[-900:],flush=True)
  sys.exit(1)
