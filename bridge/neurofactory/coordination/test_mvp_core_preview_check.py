"""Focused no-IO cross-component contract checks for CORE provider_preview v1."""
import copy
import hashlib
import json
import unittest
from mvp_core_preview_check import inspect_core_preview, CorePreviewError

def manifest(target="bridge/neurofactory/development/core_owned/demo.py"):
    return {"schema":"neurofactory.core.task.v1",
            "task_id":"NF-DEV-05-Q001","project_id":"nf-sandbox",
            "target":target,
            "objective":"Create an inert deterministic file in the isolated CORE sandbox.",
            "source_sha":"a"*40,"source_sha256":"b"*64,
            "model":"qwen2.5-coder:1.5b","reserved_units":4096,
            "approval_commit":"c"*40}

def canonical_digest(x):
    return hashlib.sha256(json.dumps(
        x,sort_keys=True,ensure_ascii=False,separators=(",",":"),
        allow_nan=False).encode("utf-8")).hexdigest()

def core_packet(spec):
    tail=spec["target"].removeprefix("bridge/neurofactory/development/core_owned/")
    target=("docs/" if tail.endswith(".md") else "src/")+tail
    d=canonical_digest(spec)
    request={"schema":"neurofactory.providers.request.v1",
             "task_id":spec["task_id"],"project_id":spec["project_id"],
             "input_sha256":d,"target_path":target,
             "instruction":spec["objective"]}
    binding={"task_id":spec["task_id"],"project_id":spec["project_id"],
             "source_sha":spec["source_sha"],"source_sha256":spec["source_sha256"],
             "core_target":spec["target"],"provider_target":target,
             "model":spec["model"],"input_sha256":d}
    return {"schema":"neurofactory.coordination.provider_bridge.v1",
            "request":request,"binding":binding,
            "permissions":{"execution":False,"retry":False,
                           "publication":False,"paid_api":False}}

class CorePacketTests(unittest.TestCase):
    def test_exact_single_file_preview_matches(self):
        p=manifest()
        wire=core_packet(p)
        p0,w0=copy.deepcopy(p),copy.deepcopy(wire)
        result=inspect_core_preview(p,wire)
        self.assertTrue(result["format_compatible"])
        self.assertEqual(result["input_sha256"],canonical_digest(p))
        self.assertEqual(result["provider_relative_path"],"src/demo.py")
        self.assertEqual(p,p0)
        self.assertEqual(wire,w0)

    def test_markdown_path_maps_only_to_docs(self):
        p=manifest("bridge/neurofactory/development/core_owned/note.md")
        self.assertEqual(inspect_core_preview(p,core_packet(p))["provider_relative_path"],
                         "docs/note.md")

    def test_nested_safe_path_is_preserved(self):
        p=manifest("bridge/neurofactory/development/core_owned/examples/demo.json")
        self.assertEqual(inspect_core_preview(p,core_packet(p))["provider_relative_path"],
                         "src/examples/demo.json")

    def test_separate_source_file_and_snapshot_hashes(self):
        p=manifest()
        result=inspect_core_preview(p,core_packet(p))
        self.assertNotEqual(result["input_sha256"],result["source_sha256"])
        self.assertNotEqual(result["source_sha"],result["source_sha256"])

    def test_rehashed_malicious_change_without_packet_rejected(self):
        p=manifest()
        packet=core_packet(p)
        p["approval_commit"]="d"*40
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,packet)

    def test_forged_recalculated_unsigned_packet_never_grants_authorization(self):
        p=manifest()
        p["approval_commit"]="d"*40
        r=inspect_core_preview(p,core_packet(p))
        for flag in ("task_source_authenticated","approval_origin_authenticated",
                     "lease_proven","source_verified","external_execution_allowed",
                     "automatic_retry_allowed","publication_allowed"):
            self.assertFalse(r[flag])
        self.assertEqual(r["handoff"],"PAUSED_BY_USER")

    def test_mismatched_source_version_refused(self):
        p=manifest()
        w=core_packet(p)
        w["binding"]["source_sha"]="f"*40
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,w)

    def test_mismatched_target_or_project_refused(self):
        for category,key,val in (("request","target_path","docs/fake.md"),
                                  ("binding","core_target","src/fake.py"),
                                  ("request","project_id","other")):
            p=manifest()
            w=core_packet(p)
            w[category][key]=val
            with self.subTest(category=category,key=key),self.assertRaises(CorePreviewError):
                inspect_core_preview(p,w)

    def test_permission_escalation_refused(self):
        for key in ("execution","retry","publication","paid_api"):
            p=manifest()
            w=core_packet(p)
            w["permissions"][key]=True
            with self.subTest(key=key),self.assertRaises(CorePreviewError):
                inspect_core_preview(p,w)

    def test_forged_additional_permission_refused(self):
        p=manifest()
        w=core_packet(p)
        w["permissions"]["review_approved"]=True
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,w)

    def test_malformed_manifest_extra_approval_rejected(self):
        p=manifest()
        p["execute"]=True
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,core_packet(p))

    def test_boolean_budget_rejected(self):
        p=manifest()
        p["reserved_units"]=True
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,core_packet(p))

    def test_windows_devices_and_directory_escape_rejected(self):
        for path in ("CON.py","LPT1.txt","dir/COM1.md","../evil.py",
                     "dir/../escape.py","sub/.hidden.py","sub//file.py"):
            p=manifest("bridge/neurofactory/development/core_owned/"+path)
            with self.subTest(path=path),self.assertRaises(CorePreviewError):
                inspect_core_preview(p,core_packet(p))

    def test_unsupported_file_type_refused(self):
        p=manifest("bridge/neurofactory/development/core_owned/a.exe")
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,core_packet(p))

    def test_no_allowance_to_self_authenticate_receipt(self):
        p=manifest()
        w=core_packet(p)
        w["reviewer"]={"name":"fake","approved":True}
        with self.assertRaises(CorePreviewError):
            inspect_core_preview(p,w)

if __name__=="__main__":
    unittest.main()
