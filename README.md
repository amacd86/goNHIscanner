# goNHIscanner

A lightweight, fast secrets scanner written in Go for Non-Human Identity (NHI) governance workflows.

Scans local directories or all repositories on a self-hosted Gitea instance for hardcoded credentials, API keys, tokens, and other secrets that represent unmanaged non-human identities.

---

## Why this exists

Most secrets scanners are designed for CI/CD pipelines — they catch secrets before they're committed. This tool is designed for a different problem: **discovering secrets that already exist across your codebase**, including in repos that predate any secrets scanning policy.

In NHI governance terms, every hardcoded credential is an unmanaged non-human identity — a service account, API key, or token with no owner, no expiry, and no rotation policy. Finding them is the first step to governing them.

---

## Features

- Scans local directories or all repos on a Gitea instance
- 13 built-in detection patterns covering AWS, GitHub, Stripe, SendGrid, Slack, database URLs, private keys, bearer tokens, and more
- Gitea mode: pulls repo list via API, clones each repo to a temp dir, scans, and cleans up automatically
- Skips binary files, build artifacts, and dependency directories (`venv`, `node_modules`, `vendor`, etc.)
- Dated report output for audit trails
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

---

## Configuration

For production use, store tokens in an env file rather than passing them as arguments:

```bash
# ~/.nhiscanner.env
GITEA_URL=http://your-gitea-host:3200
GITEA_TOKEN=your_gitea_token
GITHUB_TOKEN=your_github_token
```

Restrict permissions:
```bash
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

## Detection patterns

| Pattern | Examples caught |
|---|---|
| AWS Access Key | `AKIA...` |
| AWS Secret Key | `aws_secret_access_key = ...` |
| GitHub Token | `ghp_...`, `gho_...` |
| Generic API Key | `api_key = ...`, `apikey: ...` |
| Generic Secret | `password = ...`, `secret = ...` |
| Private Key Header | `-----BEGIN RSA PRIVATE KEY-----` |
| Bearer Token | `Authorization: Bearer ...` |
| Basic Auth in URL | `https://user:pass@host` |
| Database URL | `postgres://...`, `mongodb://...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| Stripe Key | `sk_live_...` |
| SendGrid Key | `SG....` |

---

## Roadmap

- [ ] Allowlist / false positive suppression
- [ ] JSON report output
- [ ] v2: Live service account auditor — verify discovered credentials against their APIs to confirm active, scoped, unrotated non-human identities
- [ ] Webhook alert on new findings
- [ ] GitHub Actions integration

---

## Background

Built as part of a broader NHI governance toolkit. The v2 service account auditor will extend findings from static analysis (what credentials exist in code) to live analysis (are those credentials still active, and what do they have access to?) — mirroring how enterprise ISPM tooling approaches non-human identity risk.

---

## License

MIT