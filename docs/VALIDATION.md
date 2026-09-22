# v1.0 acceptance evidence

The initial repository contained only a design, policy and untyped report schema. The v1.0 implementation completes the planned lab features.

## Verified locally

- **54 pytest tests passed** on Python 3.12 / Linux.
- Ruff lint and format checks passed; Bash and dashboard JavaScript syntax checked.
- A real read-only Linux collection emits all eight checks and validates against the shared schema. Unsupported container controls correctly return errors.
- The full synthetic fleet smoke test ingests **50 devices** and produces **20 compliant, 10 non-compliant, 10 warning and 10 unknown** results.
- Tests verify typed Windows/Linux fixtures, independent policy verdicts, weighted scores, critical failures, allowed exemptions, missing/failed evidence, policy reloads, persistent history, duplicate submissions, time ordering, age limits, authentication, body limits, stale fleet state, alert debounce and recovery/retry.

## Automated platform gates

The [verification workflow](https://github.com/alamsanan1-byte/Endpoint-compliance-agent/actions/workflows/ci.yml) contains:

1. Python/Linux tests, live Linux agent contract validation, syntax/lint checks and the 50-device demo.
2. Windows PowerShell 5.1 probe behaviour tests, schema validation of PowerShell output, live hosted Windows collection and collector tests on Windows.
3. Docker Compose image build, startup, health and authenticated API verification.

Release acceptance remains pending until these gates are green. The workflow stores the Python JUnit result as an artifact; live host inventory is not published as an artifact.

## What this evidence does not claim

Hosted CI and controlled command fixtures do not constitute tests across every Windows/Linux edition, encrypted-disk layout or desktop environment. A Windows 11 VM with BitLocker and an Ubuntu VM with LUKS should be used when extending support for a particular environment. The project is not an enterprise compliance certification, an EDR product, a vulnerability scanner or an attestation system. See the precise collection boundaries in [OPERATIONS.md](OPERATIONS.md).
