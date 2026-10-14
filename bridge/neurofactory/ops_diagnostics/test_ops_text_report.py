"""Read-only Russian summary regression tests; no credentials, network, or writes."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from io import StringIO
import unittest

from diagnose import SnapshotError
from ops_report import main, report, render_russian_text
from test_ops_report import envelope, observation


class RussianReportTests(unittest.TestCase):
    def test_text_contains_observed_workers_and_queue(self):
        value=report(envelope(observation("one")))
        text=render_russian_text(value)
        self.assertIn("ИСПОЛНИТЕЛИ",text)
        self.assertIn("runner-A",text)
        self.assertIn("ОЧЕРЕДЬ",text)
        self.assertIn("NF-DEV-05-Q091",text)
        self.assertIn("не живой мониторинг GitHub",text.lower())

    def test_recurrent_error_and_safe_advice_is_visible(self):
        value=report(envelope(observation("one",run=4,code="RECEIPT_UNKNOWN"),
                              observation("two",run=5,code="RECEIPT_UNKNOWN")))
        rendered=render_russian_text(value)
        self.assertIn("RECEIPT_UNKNOWN",rendered)
        self.assertIn("Остановить публикацию",rendered)
        self.assertIn("АВТОВОССТАНОВЛЕНИЕ",rendered)

    def test_absent_worker_and_queue_are_unknown_not_empty_success(self):
        obs=observation("one")
        obs["workers"]=[]
        obs["queue"]=[]
        rendered=render_russian_text(report(envelope(obs)))
        self.assertIn("список задач не предоставлен",rendered.lower())
        self.assertIn("список исполнителей не предоставлен",rendered.lower())

    def test_cannot_render_forged_arbitrary_dict(self):
        with self.assertRaises(SnapshotError):
            render_russian_text({"report_type":"production_success"})

    def test_human_cli_makes_no_extra_files(self):
        with TemporaryDirectory() as folder:
            doc=Path(folder)/"observed.json"
            doc.write_text(json.dumps(envelope(observation("one"))),encoding="utf-8")
            stream=StringIO()
            with redirect_stdout(stream):
                result=main([str(doc),"--format","text"])
            self.assertEqual(result,0)
            self.assertIn("ИСПОЛНИТЕЛИ",stream.getvalue())
            self.assertEqual(list(Path(folder).iterdir()),[doc])

if __name__=="__main__":
    unittest.main()
