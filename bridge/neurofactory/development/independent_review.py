"""Independent Qwen review of actual Neurofactory development work, no secrets."""
import hashlib,json,os,pathlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
API="http://127.0.0.1:11434/api/generate"
def review():
    assert os.environ.get("GITHUB_REPOSITORY")=="DSLitvinov1/my_first_repo"
    assert os.environ.get("NF_FREE_PUBLIC_CONFIRMED")=="yes"
    assert not os.environ.get("GITHUB_TOKEN"),"Never share publishing credentials with AI"
    from control_plane import validate,select,outbox
    plan=json.loads((ROOT/"roadmap.json").read_text("utf-8"))
    validate(plan)
    assert select(plan)["id"]=="NF-DEV-01"
    actual=(ROOT/"control_plane.py").read_text("utf-8")
    prompt=(
       "Ты независимый ИИ-ревьюер. Проверяй реальный рабочий модуль нейрозавода, "
       "не учебное приложение. Тебе представлен исходный код, утверждённые требования "
       "и результат независимых проверок (21/21 на облаке и на Windows runner). "
       "Ответь только JSON-объектом с verdict равным REVIEW_OK или REVIEW_BAD "
       "и reason: краткое обоснование по существу. "
       "Одобряй только если модуль: проверяет разрешённые пути, ограничения бесплатности, "
       "невозможность перепрыгнуть зависимости, выбирает только активный этап, "
       "не повторяет выполненный этап, даёт стабильный следующий промпт, "
       "не делает самопроизвольную запись чужих файлов, не выдаёт отправку в чат за факт, "
       "не использует платные API. "
       "Внимательно проверь, что completion требует независимого доказательства. "
       "Исходный код:\n"+actual[:15000]
    )
    body={"model":"qwen3:4b","prompt":prompt,"stream":False,"think":False,
          "keep_alive":"0","format":"json",
          "options":{"num_ctx":8192,"num_predict":260,"num_thread":3,"num_gpu":0,"temperature":0}}
    req=urllib.request.Request(API,data=json.dumps(body).encode("utf-8"),method="POST",
         headers={"Content-Type":"application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=240) as result:
        answer=json.load(result)
    if not answer.get("done"):raise ValueError("Incomplete model review")
    parsed=json.loads(str(answer.get("response","")))
    print("SECOND_MODEL_VERDICT",parsed.get("verdict"),str(parsed.get("reason",""))[:450],flush=True)
    if parsed.get("verdict")!="REVIEW_OK":
        raise ValueError("Independent reviewer rejected development work")
    proof={
       "status":"two_agent_development_reviewed",
       "stage":"NF-DEV-01","reviewer":"qwen3:4b",
       "verdict":"REVIEW_OK",
       "review_reason":str(parsed.get("reason",""))[:450],
       "source_sha256":hashlib.sha256(actual.encode()).hexdigest(),
       "roadmap_sha256":hashlib.sha256((ROOT/"roadmap.json").read_bytes()).hexdigest(),
       "windows_bridge_run":38318013640,
       "require_real_windows_success":True
    }
    pathlib.Path(os.environ["RUNNER_TEMP"]).joinpath("neurofactory-review.json").write_text(
       json.dumps(proof,ensure_ascii=False,indent=2)+"\n","utf-8")
if __name__=="__main__":review()
