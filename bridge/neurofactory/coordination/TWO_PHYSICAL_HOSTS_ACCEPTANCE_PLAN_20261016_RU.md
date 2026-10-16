# НЕЙРОЗАВОД — протокол проверки одной задачи на ДВУХ РЕАЛЬНЫХ хостах
Дата: 2026-10-16. Область: COORDINATOR / Issues #3,#8. Статус: `PREPARED_NOT_EXECUTED`, RELEASE BLOCKED.

## Предшествующие доказательства
- CORE exact `ce6191153d0a0c1d742de6233897186a0b46896b` — `OneTaskCore`, один локальный sandbox.
- TRUSTED HOST exact `02646ccb71b3892dc08f68a76525937cfe2ed194` — `OfflineCAS`, PostgreSQL16 `nf_test` на ОДНОМ runner, не сервер.
- COORDINATOR integrated synthetic run 38889687189: 6/6 PASS; additional blocked/UNKNOWN gap 38890797714: 8/8 PASS including demonstration of unsafe INDEPENDENT test approval; later expired-lease case code `9b24d8bd19ce177ba6adbc0fc5c631a166a105ae` (CI status must be checked, do not claim success before verified).
- All three suites are TEST-ONLY. No real OS-level signer, independent off-DB antirollback, authenticated central CAS HTTP endpoint or fenced CORE receiver exists as of this document.
- This plan authorizes NO new machine access, service deployment, secrets, paid API, real queue, real model or publication. HANDOFF remains PAUSED_BY_USER.

## Mandatory preconditions / owners / evidence
1. **COORDINATOR** verifies actual two distinct machines and permission to operate them. Each machine has its own operator-approved OS user, isolated sandbox and network identity; recording only minimal non-sensitive host identifier proofs. Two PostgreSQL connections / different processes on one hosted runner do NOT count. Record host labels A,B, coarse platform, executor account role, separate physical machine attestation by the owner; never upload raw personal/system identifiers or machine secrets.
2. **TRUSTED HOST (#14)** delivers an authenticated TLS API, central transactional CAS, persistent durable audit/backup, independently protected witness last sequence/head/key, distinct protected signer identity, signed owner/source/project/repository/policy authorization and per-effect receiver fencing. Test producer and DB owner must not be able to forge signer approval or reset the trusted external sequence.
3. **CORE (#9)** delivers separate OS-owned sandbox writer with no mutable ancestor traversal, canonical allowlisted Git source/file bytes, exact signed scope and remote receiver-side enforcement of worker, epoch, token digest, idempotency and expiry BEFORE file effect. No admin rights for model. On `UNKNOWN` or API partition: STOP, no automatic retry.
4. **REVIEW (#11)** supplies an actual separately authorized auditor/identity, checks BOTH deployed source SHAs and independently pinned logs/checkpoints, and controls targeted negative fixtures. Author's same GitHub account/chat is not sufficient as an independent release signer.
5. **OWNER** explicitly authorizes the two selected hosts, credentials, task scope, and separate service deployment. Until authorization no commands on user hosts or bridge restarts.

## Exact bounded demonstration
- Fresh isolated repo contains one INERT non-executable `docs/two-host-acceptance.txt`; owner-approved source SHA40/file SHA256/task SHA256/policy SHA256, task ID, allowed project/repo and paths are pinned and signed. No real user/customer data.
- Show that host A and B are independently authenticated with distinct host principals and can reach the SAME protected central service. Reporter reads actual host identity provenance from an out-of-band operator record, not client-supplied JSON.
- A and B simultaneously request ONE task: exactly one central `CLAIMED` with current epoch; losing client never gets the fence or writes. Capture central audit sequence and client observations. Verify only permitted principal can read the own task.
- Winning client obtains current owner/task/source/policy binding and single PRE_SIDE_EFFECT fence accepted by protected destination. Exactly one sandbox file write and readback digest; central receipt pins resulting bytes, idempotency_key and epoch. Confirm no external path touched and no implicit publishing/merge/model execution.
- Duplicate request same ID, new request with stale epoch, expired lease, stale fencing token and losing worker: target bytes identical, zero new effects; central audit records denial.
- Crash **before** side effect: no file exists; reconciliation may issue a new attempt only after independently proven zero effect and operator policy. Crash **after** file mutation but **before** receipt: `UNKNOWN`, zero automatic retries; independent reconciliation matches receiver-side idempotent record and actual target digest before any authorized progression.
- Network partition between client and API, restart of client, and central restart with restored trusted highwater: no unverified effect, no duplicated writes or rollbacks.
- Attack simulations: forged owner permit/signature, changed repo/source/target, forged review, changed signer key, DB admin reversion of history, copied old witness/sequence, fake lease/token/worker, symlink/rename and oversized requests: all deny/STOP. Never run a destructive attack on an actual service; use purpose-built disposable isolated fixtures.

## Required artifact ledger
- Both host operator identity approvals (do not expose secrets), proof machines are physically distinct and authorization scope.
- Exact source SHAs and Git tree readback before/after for HOST/CORE/COORD; audited executable Git blobs and selected pinned policy digest.
- Verifiable time-aligned logs per host, central CAS, protected external signer/sequence and fenced receiver. Record before/after output SHA256 and target path; NO token or private key in GitHub.
- Test matrix with PASS / FAIL / SKIP / INCONCLUSIVE for every scenario; raw failure histories preserved. No blanket success based on summary status.
- Independent reviewer signed verdict on EXACT executable artifacts and actual machine context; subsequent code changes invalidate previous verdict for changed bytes.
- Rollback/backup/recovery record and final release gate. A PASS on two machines alone never grants live operation or publication.

## Acceptance and stop criteria
- All protected identities and scopes authenticated, central state cannot be rolled back by DB owner, exactly one effect at an independently fenced receiver, no unauthorized file, explicit UNKNOWN reconciliation, negative scenarios denied.
- Test cannot start if any trusted key/issuer/highwater/OS isolation/permission is missing. A synthetic positive callback/fixture field, local hash alone, or two DB clients in one runner is NOT sufficient.
- Any unknown, mismatched SHA/epoch/receiver state, failed negative or missing reviewer identity => `STOP / REJECT LIVE`, keep HANDOFF paused.
- Success is recorded ONLY after actual execution on two authorized different machines with independent security review. No invented availability, time, owners or evidence.

## Next owner actions
- HOST: implement and evidence real issuer/API/fenced recipient in own branch (new exact SHA).
- CORE: consume authenticated per-effect fence in real receiver; validate allowed source/path and OS sandbox (new exact SHA).
- REVIEW: independently verify both exact changes and hostile cases before machine deployment.
- COORDINATOR: re-pin all SHA, check live operators/machines, dispatch this plan only after authorization, keep release BLOCKED meanwhile.
