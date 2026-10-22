"""One release review decision: bind three signatures, Authenticode, remote evidence.

This is intentionally an operator-only *read-only* acceptance diagnostic.
Even entirely valid cryptography does not prove actual external hardware,
private-key custody, independent human consent, physical Windows identity,
post-install ACL, or service operational authorization. No installer launch.

Never use user-provided release public keys, minimum epoch, claimed publisher
or machine as their own source of trust. All expected values are separate,
operator-provisioned read-only OS pins and fresh external witness observation.
"""
from __future__ import annotations

from pathlib import Path

from secure_release_preflight import (
    check_signed_release_preflight,
    SecureReleaseDenied,
)
from independent_witness_receipt import (
    verify_external_witness_receipt,
    IndependentWitnessDenied,
)
from windows_package_preflight import (
    inspect_windows_package,
    WindowsPackageDenied,
)

class CombinedReleaseDenied(ValueError):
    pass

def inspect_combined_release_candidate(
        *, installer: Path, signatures, pinned_release_keys,
        independently_pinned_release, now_unix,
        observed_manifest_sha256, witness_claim, witness_receipt,
        independently_pinned_witness_key,
        independently_pinned_witness_id, fresh_external_minimum_epoch,
        independently_pinned_publisher_thumbprint):
    """Combine verified evidence; always leave real authorization disabled."""
    if (not isinstance(installer, Path) or
            type(independently_pinned_release) is not dict or
            type(witness_claim) is not dict or
            type(independently_pinned_publisher_thumbprint) is not str):
        raise CombinedReleaseDenied("Operator-provisioned release inputs absent")
    try:
        rel = check_signed_release_preflight(
            signatures=signatures,pinned_keys=pinned_release_keys,
            operator_expected=independently_pinned_release,now_unix=now_unix,
            observed_installer_sha256=independently_pinned_release["installer_sha256"],
            observed_manifest_sha256=observed_manifest_sha256,
        )
        # Package signing checked against Windows Authenticode with independent
        # publisher cert thumbprint; rejects current UNSIGNED pre-release EXE.
        win = inspect_windows_package(
            installer=installer,
            expected_sha256=rel["installer_sha256"],
            pinned_publisher_thumbprint=independently_pinned_publisher_thumbprint,
        )
        if (witness_claim.get("source_sha40") != rel["candidate_sha"] or
                witness_claim.get("package_sha256") != rel["installer_sha256"] or
                witness_claim.get("machine_identity_sha256") !=
                    independently_pinned_release["machine_identity_sha256"] or
                witness_claim.get("review_evidence_sha256") !=
                    independently_pinned_release["review_evidence_sha256"] or
                witness_claim.get("external_epoch") <
                    independently_pinned_release["minimum_external_epoch"]):
            raise CombinedReleaseDenied("Witness does not bind actual release and machine")
        witness=verify_external_witness_receipt(
            claim=witness_claim,receipt=witness_receipt,
            pinned_witness_public=independently_pinned_witness_key,
            independently_pinned_witness_id=independently_pinned_witness_id,
            independently_observed_minimum_epoch=fresh_external_minimum_epoch,
            now_unix=now_unix,
        )
        if (rel["release_authorized"] is not False or
                win["production_release_allowed"] is not False or
                witness["production_install_authorized"] is not False):
            raise CombinedReleaseDenied("Unsafe caller modified test-only authority boundary")
    except (KeyError,TypeError,SecureReleaseDenied,WindowsPackageDenied,
            IndependentWitnessDenied) as exc:
        raise CombinedReleaseDenied("Required independent release evidence missing") from exc
    return {
        "schema":"nf.onepc.production_install_release_review.v1",
        "status":"SIGNED_METADATA_CONSISTENT_NOT_RELEASED",
        "source_sha40":rel["candidate_sha"],
        "installer_sha256":rel["installer_sha256"],
        "signed_release_claim_sha256":rel["signed_claim_sha256"],
        "witness_claim_sha256":witness["claim_sha256"],
        "external_epoch":witness["highest_committed_epoch"],
        "windows_publisher_signature_pinned_and_valid":True,
        "three_distinct_claim_signatures_checked":True,
        "separate_highwater_signature_checked":True,
        "real_key_custody_and_revocation_attested":False,
        "current_review_approved_by_independent_human_attested":False,
        "physical_machine_identity_attested":False,
        "remote_witness_device_independence_attested":False,
        "remote_highwater_queried_during_this_operation":False,
        "protected_scm_service_operationally_accepted":False,
        "production_installer_authorized":False,
        "service_activation_authorized":False,
        "automatic_core_host_effects_authorized":False,
    }
