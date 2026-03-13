# goNHIscanner

A lightweight, fast secrets scanner written in Go for Non-Human Identity (NHI) governance workflows.

Scans local directories or all repositories on a self-hosted Gitea instance for hardcoded credentials, API keys, tokens, and other secrets that represent unmanaged non-human identities. Includes a dark-mode PWA dashboard accessible from any device on your network or over Tailscale.

---

## Why this exists

Most secrets scanners are designed for CI/CD pipelines — they catch secrets before they're committed. This tool is designed for a different problem: **discovering secrets that already exist across your codebase**, including in repos that predate any secrets scanning policy.

In NHI governance terms, every hardcoded credential is an unmanaged non-human identity — a service account, API key, or token with no owner, no expiry, and no rotation policy. Finding them is the first step to governing them.

---

## Features

- Scans local directories or all repos on a self-hosted Gitea instance
- 13 built-in detection patterns covering AWS, GitHub, Stripe, SendGrid, Slack, database URLs, private keys, bearer tokens, and more
- High-risk pattern classification (AWS keys, GitHub tokens, private keys, Stripe keys) with red alerts
- Gitea mode: pulls repo list via API, clones each repo to a temp dir, scans, and cleans up automatically
- PWA dashboard: dark-mode web UI with repo status cards, findings trend chart, report history, and raw log viewer
- Installable as a home screen app on iOS and Android via Tailscale
- Skips binary files, build artifacts, and dependency directories (`venv`, `node_modules`, `vendor`, etc.)
- Dated report output for audit trails
- Runs as a systemd service on a Raspberry Pi
- Single static binary — no runtime dependencies

---

## Installation

### Build from source

Requires Go 1.21+

```bash
git clone https://github.com/amacd86/goNHIscanner
cd goNHIscanner
go build -o nhiscanner main.go
```

### Cross-compile for Raspberry Pi (arm64)

```bash
GOOS=linux GOARCH=arm64 go build -o nhiscanner main.go
scp nhiscanner user@your-pi:/home/user/nhiscanner
chmod +x /home/user/nhiscanner
```

---

## Usage

### Local mode

Scan a directory on your local machine:

```bash
./nhiscanner /path/to/repo
```

### Gitea mode

Scan all repositories on a Gitea instance:

```bash
./nhiscanner --gitea http://your-gitea-host:3200 YOUR_GITEA_TOKEN
```

The scanner will:
1. Fetch all repos from the Gitea API
2. Clone each repo to a temp directory
3. Scan for secrets
4. Print findings grouped by repo
5. Delete the temp directory

### Dashboard mode

Serve the PWA dashboard:

```bash
./nhiscanner --serve 3300 /path/to/reports
```

Then open `http://your-pi:3300` in any browser. On iOS/Android, tap Share → Add to Home Screen to install as a PWA.

The dashboard shows:
- Metric cards: repos scanned, clean count, total findings, high-risk count
- Red alert box for high-risk findings (AWS keys, GitHub tokens, private keys)
- Repo status grid with green/amber/red color coding
- Findings trend bar chart across all historical scans
- Report history with tap-to-expand raw log viewer

---

## Configuration

Store tokens in an env file rather than passing them as arguments:

```bash
cat > ~/.nhiscanner.env << 'EOF'
GITEA_URL=http://your-gitea-host:3200
GITEA_TOKEN=your_gitea_token
GITHUB_TOKEN=your_github_token
EOF
chmod 600 ~/.nhiscanner.env
```

Use a wrapper script for cron:

```bash
#!/bin/bash
source ~/.nhiscanner.env
/home/user/nhiscanner --gitea "$GITEA_URL" "$GITEA_TOKEN" > ~/reports/nhi-$(date +%Y-%m-%d).txt 2>&1
```

---

## Automated scanning (cron)

Run nightly at 2am, write dated reports:

```
0 2 * * * /home/user/run-nhiscanner.sh
```

---

## Running as a systemd service (Raspberry Pi)

Create `/etc/systemd/system/nhi-dashboard.service`:

```ini
[Unit]
Description=NHI Scanner Dashboard
After=network.target

[Service]
Type=simple
User=your-user
EnvironmentFile=/home/your-user/.nhiscanner.env
ExecStart=/home/your-user/nhiscanner --serve 3300 /home/your-user/reports
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl enable nhi-dashboard
sudo systemctl start nhi-dashboard
```

Access over Tailscale from anywhere: `http://your-tailscale-ip:3300`

---

## Detection patterns

| Pattern | Examples caught | Risk level |
|---|---|---|
| AWS Access Key | `AKIA...` | High |
| AWS Secret Key | `aws_secret_access_key = ...` | High |
| GitHub Token | `ghp_...`, `gho_...` | High |
| Private Key Header | `-----BEGIN RSA PRIVATE KEY-----` | High |
| Stripe Key | `sk_live_...` | High |
| Generic API Key | `api_key = ...`, `apikey: ...` | Medium |
| Generic Secret | `password = ...`, `secret = ...` | Medium |
| Bearer Token | `Authorization: Bearer ...` | Medium |
| Basic Auth in URL | `https://user:pass@host` | Medium |
| Database URL | `postgres://...`, `mongodb://...` | Medium |
| Slack Token | `xoxb-...`, `xoxp-...` | Medium |
| SendGrid Key | `SG....` | Medium |

---

## Roadmap

- [ ] Allowlist / false positive suppression
- [ ] JSON report output
- [ ] v2: Live service account auditor — verify discovered credentials against their APIs to confirm active, scoped, unrotated non-human identities
- [ ] Webhook / push notification on new high-risk findings
- [ ] GitHub Actions integration

---

## Architecture

```
goNHIscanner
├── Local mode      scan any directory on disk
├── Gitea mode      pull repo list via API → clone → scan → cleanup
└── Dashboard mode  serve PWA on :3300, reads dated report files
                    ├── /              dark-mode HTML dashboard
                    ├── /manifest.json PWA manifest
                    └── /api/reports   JSON API for report data
```

The scanner runs nightly via cron, writes dated `.txt` reports, and the dashboard reads them at request time — no database required.

---

## Background

Built as part of a broader NHI governance toolkit. The v2 service account auditor will extend findings from static analysis (what credentials exist in code) to live analysis (are those credentials still active, and what do they have access to?) — mirroring how enterprise ISPM tooling approaches non-human identity risk.

---

## License

MIT