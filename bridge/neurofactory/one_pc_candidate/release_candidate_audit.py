"""One-PC candidate coherence, NOT a production release authorization.

Read sources only; no service launch, model call, billing, account/login,
artifact download or source writes. Pin the previously independently observed
CI evidence in source. This is a consistency preflight, not a cryptographic
reviewer signature nor remote workflow attestation.
"""
from __future__ import annotations
from pathlib import Path
import json
import re

CORE_PIN="1c4ccd7d64e87e284a3796b3432f13910a48679c"
EXPECTED_FILES=15
INSTALLER_WINDOWS_RUN=39701930342
SCM_HOST_WINDOWS_RUN=39702159425
INSTALLER_DIGEST="648DC60F51390578C1835CA46B5151B61F1CB64858C34D6E164A8092381E35CF"
PYTHON_VENDOR_DIGEST="4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3"

class ReleaseCandidateDenied(ValueError):
    pass

def verify(root):
    root=Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ReleaseCandidateDenied("Cannot verify outside explicitly rooted checkout")
    one=root/"bridge/neurofactory/one_pc_candidate"
    ui=root/"bridge/neurofactory/control_ui"
    wf=root/".github/workflows"
    def read(file):
        if file.is_symlink() or not file.is_file():
            raise ReleaseCandidateDenied("Missing or linked candidate file")
        return file.read_text(encoding="utf-8")
    core=read(root/"bridge/neurofactory/development/core_owned/one_task_core.py")
    stage=read(one/"stage_runtime_sources.py")
    integrity=read(one/"installed_integrity.py")
    installer=read(wf/"neurofactory-onepc-installer.yml")
    scm=read(wf/"neurofactory-onepc-final-scm-close.yml")
    inno=read(one/"windows_setup/NeurofactoryLocalDraft.iss")
    backend=read(one/"local_workspace.py")
    adapter=read(one/"codex_sites_bridge.py")
    selfdev=read(one/"selfdev_review_candidate.py")
    html=read(ui/"index.html")
    nav=read(ui/"integrations.js")
    sources=[
        (CORE_PIN in stage and CORE_PIN in integrity,
         "CORE_GIT_SHA_WRONG"),
        (CORE_PIN in installer and CORE_PIN in scm,
         "WINDOWS_WORKFLOWS_NOT_PINNED"),
        ("CREATE_NO_WINDOW" in core,
         "WINDOWS_SCM_GIT_CHILD_FIX_MISSING"),
        ('("one_task_core.py",)' in stage and '("one_task_core.py",)' in integrity,
         "OLD_CORE_CLIENT_REINTRODUCED"),
        ("offline_os_receiver_client.py" not in stage and
         "offline_os_receiver_client.py" not in integrity,
         "OBSOLETE_CORE_SOURCE_INCLUDED"),
        ('"core/one_task_core.py": "b43f4217f0756154fe3d3e6fafd007762c5b5117"' in integrity,
         "PINNED_CORE_BLOB_UNVERIFIED"),
        ("VENDOR_RUNTIME_SHA256_NOT_PINNED" in installer and
         PYTHON_VENDOR_DIGEST in installer,
         "EMBEDDED_RUNTIME_UNVERIFIED"),
        ("$manifest.entries.Count -ne 15" in installer and
         "stamp[\"files_verified\"]!=15" in read(one/"draft_provider.py"),
         "COMPONENT_COUNT_DRIFT"),
        ("PrivilegesRequired=lowest" in inno and
         "windows_scm_core_admission_ci.py" not in inno and
         "windows_owner_controller_candidate.py" not in inno and
         "windows_scm_core_admission_ci.py" not in backend,
         "USER_INSTALLER_BUNDLES_PRIVILEGED_SERVICE"),
        ('"/integrations.js": "integrations.js"' in backend and
         '<script defer src="integrations.js"></script>' in html and
         "Codex и Sites" in nav and "codex_sites_bridge.py" in inno,
         "CODEX_SITES_NOT_STAGED"),
        ("selfdev_sandbox/" in selfdev and
         "DISPOSABLE_REVIEWED_SOURCE_TO_PATCH_NO_APPLY_NO_PR" in selfdev and
         "production_authorized" in selfdev,
         "SELFDEV_FAIL_CLOSED_BOUNDARY_MISSING"),
        ("NF_ONEPC_FINAL_SIGNED_CI" in scm and
         "NF_ONEPC_PROVIDER_CORE_HOST_CI" in scm,
         "REAL_SCM_HOST_SIGNED_CORE_TEST_NOT_CONFIGURED"),
    ]
    for valid,reason in sources:
        if not valid:
            raise ReleaseCandidateDenied(reason)
    result={
        "schema":"nf.onepc.release_candidate_coherence.v1",
        "status":"UNRELEASED_REVIEW_BLOCKED",
        "core_source_git_sha":CORE_PIN,
        "inert_packaged_components":EXPECTED_FILES,
        "observed_windows_installer_ci_run":INSTALLER_WINDOWS_RUN,
        "observed_windows_scm_host_ci_run":SCM_HOST_WINDOWS_RUN,
        "observed_installer_sha256":INSTALLER_DIGEST,
        "pinned_python_sha256":PYTHON_VENDOR_DIGEST,
        "owner_pc_installed":False,
        "protected_production_scm_service_installed":False,
        "independent_review_approved":False,
        "owner_production_key_enrolled":False,
        "production_antireplay_witness":False,
        "production_release_authorized":False,
        "auto_execution_allowed":False,
        "skills_activated":False,
        "codex_account_authenticated_on_owner_pc":False,
        "sites_publishing_allowed":False,
        "assessment":"STATIC_SOURCE_COHERENCE_NOT_RUNTIME_ATTESTATION",
    }
    return result

if __name__=="__main__":
    result=verify(Path(__file__).resolve().parents[3])
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    print("NF_UNIFIED_CANDIDATE_SOURCE_COHERENCE=PASS_NO_RELEASE")
