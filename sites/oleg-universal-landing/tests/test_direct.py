from pathlib import Path
import csv
from urllib.parse import parse_qs, urlparse
root=Path(__file__).resolve().parents[1]
with (root/"seo/direct-structure.csv").open(encoding="utf-8-sig",newline="") as f:
    rows=list(csv.DictReader(f,delimiter=";"))
assert len(rows)==7
for row in rows:
    title=row["Заголовок"]
    body=row["Текст"]
    assert 0 < len(title) <= 56, title
    assert 0 < len(body) <= 81, body
    assert max(map(len,title.split()))<=22
    assert max(map(len,body.split()))<=23
    params=parse_qs(urlparse(row["Ссылка относительно нового домена"]).query)
    assert params["topic"][0] == row["Тема формы"]
    assert params["utm_campaign"][0] == row["UTM кампания"]
    assert params["utm_source"][0] == "yandex"
    assert params["utm_medium"][0] == "cpc"
    assert params["utm_content"][0] == "{ad_id}"
    assert row["Статус"].startswith("Черновик")
    assert "семейное" not in row["Группа"].lower()
    assert "потребител" not in row["Группа"].lower()
assert len({r["UTM кампания"] for r in rows})==len(rows)
print("PASS: 7 Yandex Direct ad groups, topic routing, unique UTM, text limits, no live launch")
