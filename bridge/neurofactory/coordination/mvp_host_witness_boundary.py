"""COORDINATOR: correlate untrusted CORE/HOST diagnostics, never grant authority."""
import re

class BoundaryError(ValueError):
    pass

_SHA40 = re.compile(r'[0-9a-f]{40}\Z')
_SHA64 = re.compile(r'[0-9a-f]{64}\Z')
_TASK = re.compile(r'NF-DEV-05-Q[0-9]{3}\Z')
_PATH = re.compile(r'(?:docs|src)/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z')
_CORE = {'schema','task_id','source_sha','source_sha256','input_sha256',
    'provider_relative_path','format_compatible','task_source_authenticated',
    'approval_origin_authenticated','lease_proven','source_verified',
    'external_execution_allowed','automatic_retry_allowed','publication_allowed','handoff'}
_HOST = {'schema','task_id','status','witness_receipt_sha256',
    'checkpoint_matches_signed_witness','externally_pinned_key_provenance_attested',
    'externally_pinned_witness_sequence_durably_protected',
    'independent_host_operator_approval','live_execution_allowed',
    'publication_allowed','automatic_retry_allowed','handoff'}

def _match(v,pattern):
    return type(v) is str and pattern.fullmatch(v) is not None

_WINDOWS_DEVICES = frozenset({'CON','PRN','AUX','NUL'} |
    {'COM'+str(i) for i in range(1,10)} |
    {'LPT'+str(i) for i in range(1,10)})

def _safe_provider_path(path):
    if not _match(path,_PATH) or len(path)>115:
        return False
    parts=path.split('/')
    if parts[0]=='docs':
        if not path.endswith('.md'):
            return False
    elif not path.endswith(('.py','.txt','.json')):
        return False
    return all(
        x not in ('','.','..') and
        not x.startswith('.') and not x.endswith('.') and
        x.split('.')[0].upper() not in _WINDOWS_DEVICES
        for x in parts[1:]
    )

def inspect_host_witness(core, host, *, expected_task_id):
    """Read-only report. Positive source/host checks cannot authorize any work."""
    if (not _match(expected_task_id,_TASK) or type(core) is not dict or
        set(core)!=_CORE or type(host) is not dict or set(host)!=_HOST):
        raise BoundaryError('unexpected report fields')
    if (core['schema']!='neurofactory.coordination.core_preview_inspection.v1' or
        core['task_id']!=expected_task_id or
        not _match(core['source_sha'],_SHA40) or
        not _match(core['source_sha256'],_SHA64) or
        not _match(core['input_sha256'],_SHA64) or
        not _safe_provider_path(core['provider_relative_path']) or
        core['format_compatible'] is not True or
        any(core[k] is not False for k in ('task_source_authenticated',
            'approval_origin_authenticated','lease_proven','source_verified',
            'external_execution_allowed','automatic_retry_allowed','publication_allowed')) or
        core['handoff']!='PAUSED_BY_USER'):
        raise BoundaryError('invalid or elevated CORE preview')
    match='SIGNED_WITNESS_MATCHES_TEST_DB'
    if (host['schema']!='neurofactory.trusted_host.offline_witness_comparison.v1' or
        host['task_id']!=expected_task_id or
        host['status'] not in (match,'UNKNOWN_OR_ROLLBACK') or
        not _match(host['witness_receipt_sha256'],_SHA64) or
        host['checkpoint_matches_signed_witness'] is not (host['status']==match) or
        any(host[k] is not False for k in ('externally_pinned_key_provenance_attested',
            'externally_pinned_witness_sequence_durably_protected',
            'independent_host_operator_approval','live_execution_allowed',
            'publication_allowed','automatic_retry_allowed')) or
        host['handoff']!='PAUSED_BY_USER'):
        raise BoundaryError('invalid or elevated HOST witness')
    return {
        'schema':'neurofactory.coordination.host_witness_boundary.v1',
        'task_id':expected_task_id,'diagnostic_status':host['status'],
        'proposed_core_sha40':core['source_sha'],
        'proposed_source_file_sha256':core['source_sha256'],
        'proposed_input_task_sha256':core['input_sha256'],
        'proposed_provider_target':core['provider_relative_path'],
        'provenance_authenticated':False,'owner_authorization_verified':False,
        'policy_sha256_authenticated':False,'signed_target_binding_verified':False,
        'witness_contains_signed_source_fields':False,
        'protected_issuer_highwater_verified':False,
        'central_cas_and_receiver_fencing_verified':False,
        'independent_exact_sha_release_review_verified':False,
        'live_execution_allowed':False,'automatic_retry_allowed':False,
        'publication_allowed':False,'handoff':'PAUSED_BY_USER',
        'integration_gate':'BLOCKED_NONLIVE_DIAGNOSTIC_ONLY'}
