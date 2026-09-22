# Operating the lab

## Collector configuration

Use Python 3.12 for the collector and install `requirements.lock` (runtime only) or `requirements-dev.lock` (tests included). `.env` is read automatically by Docker Compose; a plain `uvicorn` process reads exported environment variables, not `.env` files.

| Variable | Purpose |
|---|---|
| `API_KEY` | Required shared secret, at least 24 characters; generate with `secrets.token_urlsafe(32)` |
| `DATABASE_PATH` | Default `data/compliance.db` |
| `POLICY_PATH` | Default repository `policy/baseline.yaml` |
| `WEBHOOK_URL` | Optional HTTPS destination; blank disables all external alert traffic |
| `COLLECTOR_URL` | Agent destination; default `http://127.0.0.1:8000` |
| `DEVICE_ID` | Optional agent identity override |

Run a single collector worker for this SQLite lab. Back up the database using SQLite's online backup API, or stop the collector before copying the database and sidecars. Report history is retained until the lab operator removes it; there is no automatic retention job. Collection timestamp determines the newest state. If two distinct reports have the same timestamp, the most recently received wins.

Update policy atomically (write a temporary file and rename it) to avoid transient `503` responses during partial writes. Fleet views update immediately; webhook evaluation happens only when a fresh latest report arrives. Staleness is computed when the fleet is queried; there is no background missing-device alert worker.

## Linux server scheduling

Copy this repository to `/opt/endpoint-compliance`. On the lab endpoint, create `/etc/endpoint-compliance.env` with a locally generated key and the HTTPS collector address:

```text
API_KEY=your-generated-secret
COLLECTOR_URL=https://collector.example.test
DEVICE_ID=LAB-LINUX-01
```

Restrict that file to root, then install the supplied templates:

```bash
sudo chmod 600 /etc/endpoint-compliance.env
sudo cp deployment/linux/endpoint-compliance.service /etc/systemd/system/
sudo cp deployment/linux/endpoint-compliance.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now endpoint-compliance.timer
sudo systemctl start endpoint-compliance.service
sudo systemctl status endpoint-compliance.service
```

These commands are **operator-run setup instructions**, not automatic actions by the agent. The template runs hourly with jitter and stores a private latest report under `/var/lib/endpoint-compliance`. It uses `--headless` and is specifically for a server without an interactive desktop. A desktop requires collection in the user's GNOME session, plus sufficient privileges for system probes; unavailable probes remain errors. Do not use `--headless` simply to conceal a desktop probe failure.

To remove the schedule:

```bash
sudo systemctl disable --now endpoint-compliance.timer
```

## Windows scheduling

Use an elevated **64-bit Windows PowerShell 5.1** session. Store the API key in a file outside the repository, such as `C:\ProgramData\EndpointComplianceKey.txt`, and restrict it to SYSTEM and Administrators:

```powershell
icacls.exe C:\ProgramData\EndpointComplianceKey.txt /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
.\deployment\windows-register-task.ps1 `
    -RepositoryPath C:\Projects\Endpoint-compliance-agent `
    -CollectorUrl https://collector.example.test `
    -ApiKeyFile C:\ProgramData\EndpointComplianceKey.txt
Start-ScheduledTask -TaskName 'Endpoint Compliance Agent'
Get-ScheduledTaskInfo -TaskName 'Endpoint Compliance Agent'
```

The task runs hourly as SYSTEM; the key is loaded at execution and is not placed in the task's command line. Its latest report is stored under a restricted `C:\ProgramData\EndpointCompliance` directory. Keep the repository and scripts writable only by trusted administrators. Respect the machine's execution policy; the template does not bypass it. Sign scripts or use an approved local policy as appropriate for your lab.

Remove the schedule using `Unregister-ScheduledTask -TaskName 'Endpoint Compliance Agent'` when finished.

## Offline behaviour

Use `--output` / `-OutputPath` to save evidence before attempting submission. Failed submission returns a nonzero exit status, preserving the local report. Scheduled runs collect fresh evidence on the next interval. There is **no automatic backlog queue**; the latest scheduled snapshot replaces the previous one. An operator can submit a saved report within the allowed age window. JSON printed to the terminal may contain sensitive inventory; do not paste real reports into public issues.

## Webhooks

Set an HTTPS `WEBHOOK_URL` only for a destination you control. The collector sends a generic JSON object containing device ID, score, state, failing control IDs and policy hash; this is not a Slack/Teams-specific envelope. It does not send the full software inventory. No redirects are followed. TLS certificate verification stays enabled.

A successfully delivered signature is suppressed for the configured cooldown (60 minutes by default). A changed set of control states can alert immediately. A fresh compliant report clears the debounce entry so a later regression alerts again. Failed deliveries leave no successful-send record and retry on the next fresh latest report. Duplicates and historical reports do not alert. A process crash between delivery and recording can cause a later duplicate: this is not exactly-once delivery.

## Probe limitations and interpretation

- **BitLocker/LUKS:** operating-system/root storage only, not every data disk. Containers and hidden root devices return an error. Hardware encryption outside the inspected provider is unsupported.
- **Patching:** update age is a proxy. An unrelated package install can refresh it; hotfix inventory does not include every update mechanism. No vulnerability feed or available-update scan is performed.
- **Firewall:** checks the supported manager/profile state, not whether individual rules are safe. Custom nftables/iptables-only setups cannot be verified.
- **Antivirus:** Defender on Windows, ClamAV daemon on Linux. A running ClamAV daemon is not proof of on-access scanning. Other products return an unsupported-provider error.
- **Administrators:** nested domain groups are retained as names, not expanded. Linux custom sudoers/polkit permissions are not parsed. The allowlist must be reviewed for the actual lab and naming conventions.
- **Screen lock:** Windows uses the machine inactivity policy, not per-user screen saver policy. Linux supports only the active GNOME session. An explicit headless exception is operator asserted, not remotely attested.
- **Reboot:** supported platform signals only; not every installer sets these flags.
- **Software:** Windows machine-wide registry packages and dpkg/RPM only; the blocklist matches complete names case-insensitively, not substrings or versions.

## Troubleshooting

- `401`: the agent/dashboard key does not match the collector key.
- `422`: invalid/missing typed values, duplicate check IDs, stale/future timestamp or an invalid device ID. Missing *controls* are accepted but evaluated as errors.
- `503`: invalid/unreadable policy. Restore a valid baseline; no collector restart is needed.
- An endpoint is `unknown`: inspect each control's detail; permissions and unavailable tools are separate from confirmed policy failures.
- A device is stale: collection is older than `stale_after_hours`; its last score is not current evidence.
- A recent package update still fails: thresholds are central and may be stricter than the sample defaults.
- Linux identity collision in cloned VMs: provide unique enrolled device IDs or regenerate machine IDs using your distribution's VM-cloning process.

## Source references

The probes use documented OS interfaces:

- [Microsoft BitLocker operations](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [Microsoft Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)
- [Machine inactivity policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)
- [lsblk reference](https://man7.org/linux/man-pages/man8/lsblk.8.html)
- [ClamAV scanning components](https://docs.clamav.net/manual/Usage/Scanning.html)
- [FastAPI application lifespan](https://fastapi.tiangolo.com/advanced/events/)
