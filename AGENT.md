# Bug Hunter Agent

## Overview
Comprehensive bug-hunting agent that uses skills from `/home/Dark-Knight/skills/` to find vulnerabilities on any given target.

## Usage with Your Data

If you already have recon data (subdomains, endpoints, JS files), use these scripts:

### Step 1: Run the Hunt
```bash
/home/Dark-Knight/agent/bug-hunter/scripts/hunt.sh <target> <data_dir>
```

**Example:**
```bash
# Your data is in /tmp/my-target/
/home/Dark-Knight/agent/bug-hunter/scripts/hunt.sh example.com /tmp/my-target/
```

### Step 2: Generate Report
```bash
/home/Dark-Knight/agent/bug-hunter/scripts/report.sh <target> <data_dir>
```

**Example:**
```bash
/home/Dark-Knight/agent/bug-hunter/scripts/report.sh example.com /tmp/my-target/
```

## Scripts Available

| Script | Purpose |
|--------|---------|
| `hunt.sh` | Run full bug hunt on existing data |
| `report.sh` | Generate markdown report |
| `analyze.sh` | Analyze specific data files |
| `recon.sh` | Run recon from scratch (if you don't have data) |
| `vulntest.sh` | Manual vuln testing |

## Data Format

The hunt script expects your data in the data directory:
```
/tmp/my-target/
├── subs.txt          # Subdomains (one per line)
├── endpoints.txt     # URLs/endpoints (one per line)
└── js/               # JavaScript files (*.js)
```

Or any combination:
```
/tmp/my-target/
├── alive.txt         # Live hosts from httpx
├── probe.json        # httpx JSON output
├── crawled.txt       # Crawled URLs
└── js/               # Downloaded JS files
```

## What It Finds

### 🔐 Secrets
- AWS Keys (AKIA, ASIA)
- Azure/GCP Keys
- JWT Tokens
- API Keys
- Hardcoded Passwords
- S3 Buckets
- Firebase URLs

### 🎯 Endpoints
- API endpoints (/api/*, /graphql)
- Admin panels (/admin, /dashboard)
- Auth endpoints (/login, /reset-password)
- File upload endpoints
- Sensitive files (.env, .json, .bak)

### ⚡ Vulnerable Parameters
- XSS test points (search=, q=, s=)
- SQLi test points (id=, user=, order=)
- SSRF test points (url=, dest=, redirect=)
- LFI test points (file=, path=, document=)

### 🔍 Subdomain Takeover
- Dev/staging subdomains
- Cloud resources (S3, Heroku, etc)
- Internal naming patterns

## Output

Results are saved to:
```
<data_dir>/hunt-results/
├── bug-hunter-report.md    # Final report
├── js-analysis/            # JS findings
├── endpoints/              # Endpoint analysis
├── vulns/                  # Vulnerable parameters
├── secrets/                # Found secrets
└── takeover/               # Takeover targets
```

## Skills Used

| Skill Source | File | What It Tests |
|--------------|------|---------------|
| **JSMAX** | `../skills/jsmax/SKILL.md` | Secrets in JS, tokens, keys |
| **BBH XSS** | `../skills/bbh_skills/bbh-xss.md` | XSS patterns |
| **BBH SQLi** | `../skills/bbh_skills/bbh-sqli.md` | SQL injection |
| **BBH SSRF** | `../skills/bbh_skills/bbh-ssrf.md` | SSRF patterns |
| **BBH LFI** | `../skills/bbh_skills/bbh-lfi.md` | LFI patterns |
| **BBH IDOR** | `../skills/bbh_skills/bbh-idor.md` | IDOR patterns |
| **BBH Recon** | `../skills/bbh_skills/bbh-recon-takeover.md` | Takeover |
| **Hermes ATO** | `../skills/hermes-bug-bounty/hunt-ato/` | Access takeover |
| **Hermes Auth** | `../skills/hermes-bug-bounty/hunt-auth-bypass/` | Auth bypass |

## Quick Start

```bash
# Run hunt on your existing data
/home/Dark-Knight/agent/bug-hunter/scripts/hunt.sh target.com /path/to/your/data

# Generate report
/home/Dark-Knight/agent/bug-hunter/scripts/report.sh target.com /path/to/your/data
```