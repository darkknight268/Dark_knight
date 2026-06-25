# Bug Hunter Recon 🎯

Fully automated bug bounty reconnaissance pipeline — 9 phases, 20+ subdomain sources, comprehensive vulnerability detection.

## Quick Start

```bash
# One-command full recon
./scripts/recon.sh target.com

# Results in /tmp/bug-hunter-target.com/
```

## What It Does

| Phase | Description |
|-------|-------------|
| **1** | Subdomain enumeration (20 sources) |
| **2** | IP resolution, DNS deep dive, takeover checks |
| **3** | Live web probing with status-code separation |
| **4** | Technology & WAF fingerprinting |
| **5** | Port scanning (top 1000) |
| **6** | Endpoint discovery (7 tools) |
| **7** | Parameter extraction (gf patterns) |
| **8** | JavaScript collection & secret scanning |
| **9** | Automated bug detection (SSTI, LFI, SQLi, XSS, SSRF, CORS, XXE, JWT, etc.) |

## Tools Required

### Core (install these):
```bash
# Install via go install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/tomnomnom/hakrawler@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/kxss@latest
pip3 install arjun
pip3 install paramspider
```

### Also need:
- **nuclei-templates**: `git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates`
- **sublist3r**: `pip3 install sublist3r` or `git clone https://github.com/aboul3la/Sublist3r`
- **findomain**: Download from https://github.com/Findomain/Findomain/releases
- **amassfinder**: `pip3 install amassfinder` or custom script
- **censys**: `pip3 install censys`
- **nmap**: `apt install nmap`

## API Keys Setup

Copy and edit the config file:

```bash
cp scripts/recon.cfg scripts/recon.cfg.local
# Edit with your keys
```

Or just edit `recon.cfg` directly. The script auto-loads it. **No keys = no problem** — tools that need keys silently skip if not set.

Keys you already have configured (from subfinder):
- Chaos, Censys, Shodan, VirusTotal, GitHub, FullHunt, AlienVault, BeVigil, BufferOver, DNSDumpster, FOFA, LeakIX, WhoIsXMLAPI, ZoomEye

## Output Structure

```
/tmp/bug-hunter-target.com/
├── subs.uniq                 # All unique subdomains
├── ips.txt                   # Resolved IPs
├── alive.txt                 # Live web hosts
├── alive200.txt              # Hosts by status code
├── alive401.txt
├── probe.json                # httpx full results
├── ports.json / open_ports.txt
├── allendpoints.txt          # All discovered URLs
├── juicy.urls                # High-value endpoints
├── params/                   # GF-parameterized URLs
│   ├── xss.txt / ssrf.txt / lfi.txt / sqli.txt / ssti.txt
├── js.urls                   # JavaScript files
├── js_secrets.json           # Secrets found in JS
├── bugs/                     # Vulnerability findings
│   ├── xss_reflected.txt
│   ├── ssti.txt / lfi.txt / sqli.json
│   ├── open_redirects.txt
│   ├── cors.json / cors_reflected.txt
│   ├── graphql.txt / session_fixation.txt
│   ├── jwt_tokens.txt
│   └── ...
```

## Usage Examples

```bash
# Full recon on a target
./scripts/recon.sh example.com

# Use with existing data (other scripts)
./scripts/hunt.sh example.com /tmp/my-data/
./scripts/report.sh example.com /tmp/my-data/
```

## Pushing to GitHub

```bash
# Initialize repo
cd /home/Dark-Knight/agent/bug-hunter
git init
git add README.md scripts/ AGENT.md SKILL.md
git commit -m "Initial commit: Bug Hunter Recon pipeline"

# Add remote and push
git remote add origin https://github.com/YOUR_USERNAME/bug-hunter.git
git branch -M main
git push -u origin main
```

> ⚠️ **Don't commit `recon.cfg` with real keys** — add it to `.gitignore`:
> ```bash
> echo "scripts/recon.cfg" >> .gitignore
> git add .gitignore
> git commit -m "Add gitignore"
> ```
> Instead, commit `recon.cfg` as `recon.cfg.example` with empty values, and tell users to copy it.

## Contributing

PRs welcome. Keep it modular, add `|| true` to all commands so failures don't halt the pipeline.
