#!/usr/bin/env python3
import os
import sys
import json
import datetime
from pathlib import Path

def read_lines_safe(file_path):
    p = Path(file_path)
    if not p.exists():
        return []
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Error reading {file_path}: {e}")
        return []

def read_json_lines_safe(file_path):
    p = Path(file_path)
    if not p.exists():
        return []
    results = []
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    try:
                        results.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"[-] Error reading json lines {file_path}: {e}")
    return results

def resolve_remote_url(local_path, data_dir):
    import hashlib
    local_path_str = str(local_path)
    filename = Path(local_path).name
    stem = Path(local_path).stem
    
    # Load js.urls, jsfile.txt, downloaded.txt, crawled.txt to find remote URL mapping
    urls = []
    for filename_to_check in ["js.urls", "jsfile.txt", "downloaded.txt", "crawled.txt"]:
        p = Path(data_dir) / filename_to_check
        if p.exists():
            urls.extend(read_lines_safe(p))
        p_sub = Path(data_dir) / "hunt-results" / filename_to_check
        if p_sub.exists():
            urls.extend(read_lines_safe(p_sub))
            
    urls = list(set(urls))
    
    # Try 1: Match by MD5 hash of the URL
    for url in urls:
        url_clean = url.split("?")[0]
        # Check standard MD5
        if hashlib.md5(url.encode('utf-8')).hexdigest() == stem or hashlib.md5(url_clean.encode('utf-8')).hexdigest() == stem:
            return url
        # Check MD5 of protocol-stripped URL
        url_stripped = url_clean.replace("https://", "").replace("http://", "")
        if hashlib.md5(url_stripped.encode('utf-8')).hexdigest() == stem:
            return url
            
    # Try 2: Suffix matching (e.g. local path ends in /js/app.js matching https://mock.com/js/app.js)
    parts = Path(local_path).parts
    for i in range(len(parts)):
        suffix_path = "/".join(parts[i:])
        if suffix_path.endswith(".js"):
            for url in urls:
                url_clean = url.split("?")[0]
                if url_clean.endswith(suffix_path):
                    return url
                    
    # Try 3: Filename matching (fallback)
    for url in urls:
        url_clean = url.split("?")[0]
        if Path(url_clean).name == filename:
            return url
            
    # Try 4: Domain reconstruction (if path contains target domain name)
    for part in parts:
        if "." in part and len(part) > 3 and not part.startswith("tmp") and not part.startswith("bug-hunter"):
            idx = parts.index(part)
            return "https://" + "/".join(parts[idx:])
            
    return local_path_str

def main():
    if len(sys.argv) < 3:
        print("Usage: generate_dashboard.py <target> <data_dir>")
        sys.exit(1)

    target = sys.argv[1]
    data_dir = Path(sys.argv[2])
    hunt_dir = data_dir / "hunt-results"
    
    print(f"[*] Starting dashboard generation for: {target}")
    print(f"[*] Data directory: {data_dir}")

    # Initialize structure
    db = {
        "target": target,
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "subdomains": 0,
            "live_hosts": 0,
            "open_ports": 0,
            "endpoints": 0,
            "secrets": 0,
            "vulns": 0,
            "takeovers": 0,
            "wafs": 0,
            "juicy_endpoints": 0,
            "js_files": 0
        },
        "subdomains": [],
        "endpoints": [],
        "secrets": {},
        "vulnerabilities": {}
    }

    # 1. Parse Subdomains & DNS
    # Look for resolved subdomains from probe.json first (highly detailed)
    probe_file = data_dir / "probe.json"
    probe_results = read_json_lines_safe(probe_file)
    probed_domains = {}
    for r in probe_results:
        domain = r.get("input") or r.get("host")
        if domain:
            # Clean protocol prefix if present
            domain_clean = domain.replace("https://", "").replace("http://", "").split(":")[0]
            probed_domains[domain_clean] = {
                "domain": domain_clean,
                "status": r.get("status_code"),
                "ips": r.get("ip"),
                "tech": r.get("tech", []),
                "cname": r.get("cname", "")
            }

    # Fallback to dns_a.txt for DNS details
    dns_a_file = data_dir / "dns_a.txt"
    dns_a_lines = read_lines_safe(dns_a_file)
    dns_ips = {}
    for line in dns_a_lines:
        # Example dnsx format: sub.target.com [1.2.3.4] or sub.target.com [A] 1.2.3.4
        parts = line.split()
        if len(parts) >= 2:
            dom = parts[0]
            ip = parts[-1].strip("[]")
            dns_ips[dom] = ip

    # Read all unique subdomains
    subs_uniq_file = data_dir / "subs.uniq"
    all_subs = read_lines_safe(subs_uniq_file)
    db["stats"]["subdomains"] = len(all_subs)

    for sub in all_subs:
        if sub in probed_domains:
            db["subdomains"].append(probed_domains[sub])
        else:
            db["subdomains"].append({
                "domain": sub,
                "status": None,
                "ips": dns_ips.get(sub, None),
                "tech": [],
                "cname": ""
            })

    # Count live hosts
    alive_file = data_dir / "alive.txt"
    db["stats"]["live_hosts"] = len(read_lines_safe(alive_file))

    # 2. Parse Open Ports
    open_ports_file = data_dir / "open_ports.txt"
    ports_lines = read_lines_safe(open_ports_file)
    db["stats"]["open_ports"] = len(ports_lines)

    # 3. Parse Endpoints
    endpoint_files = {
        "api": hunt_dir / "endpoints/api.txt",
        "admin": hunt_dir / "endpoints/admin.txt",
        "auth": hunt_dir / "endpoints/auth.txt",
        "upload": hunt_dir / "endpoints/upload.txt",
        "sensitive": hunt_dir / "endpoints/sensitive.txt"
    }

    seen_endpoints = set()
    for cat, filepath in endpoint_files.items():
        lines = read_lines_safe(filepath)
        for url in lines:
            if url not in seen_endpoints:
                seen_endpoints.add(url)
                db["endpoints"].append({"url": url, "category": cat})

    # Read remaining endpoints
    all_endpoints = read_lines_safe(data_dir / "allendpoints.txt")
    for url in all_endpoints:
        if url not in seen_endpoints:
            # Simple category detection
            cat = "other"
            url_lower = url.lower()
            if "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower or "graphql" in url_lower:
                cat = "api"
            elif any(x in url_lower for x in ["admin", "dashboard", "panel"]):
                cat = "admin"
            elif any(x in url_lower for x in ["login", "auth", "signin", "signup"]):
                cat = "auth"
            elif "upload" in url_lower:
                cat = "upload"
            elif url_lower.endswith((".env", ".sql", ".bak", ".config", ".yaml", ".yml", ".json")):
                cat = "sensitive"
            
            db["endpoints"].append({"url": url, "category": cat})
            seen_endpoints.add(url)

    db["stats"]["endpoints"] = len(db["endpoints"])

    # 4. Parse Secrets
    secret_files = {
        "aws_keys": hunt_dir / "secrets/aws_keys.txt",
        "azure_connections": hunt_dir / "secrets/azure.txt",
        "gcp_keys": hunt_dir / "secrets/gcp.txt",
        "jwt_tokens": hunt_dir / "secrets/jwt.txt",
        "api_keys": hunt_dir / "secrets/api_keys.txt",
        "passwords": hunt_dir / "secrets/passwords.txt",
        "s3_buckets": hunt_dir / "secrets/s3_buckets.txt",
        "firebase_urls": hunt_dir / "secrets/firebase.txt"
    }

    secrets_count = 0
    for key, filepath in secret_files.items():
        db["secrets"][key] = []
        lines = read_lines_safe(filepath)
        # Deduplicate by full line (value|||source pair)
        unique_matches = set(lines)
        for match in unique_matches:
            # Format: SECRET_VALUE|||/path/to/source.js  (written by hunt.sh)
            # Fallback: plain value with no source info
            if "|||" in match:
                value, source = match.rsplit("|||", 1)
                value = value.strip()
                source = source.strip()
                source = resolve_remote_url(source, data_dir)
            else:
                value = match.strip()
                source = "JS Static Asset"
            if value:
                db["secrets"][key].append({"value": value, "source": source})
                secrets_count += 1

    db["stats"]["secrets"] = secrets_count

    # 5. Parse Vulnerability Indicators
    vuln_files = {
        "xss_parameters": hunt_dir / "vulns/xss_params.txt",
        "sqli_parameters": hunt_dir / "vulns/sqli_params.txt",
        "ssrf_parameters": hunt_dir / "vulns/ssrf_params.txt",
        "lfi_parameters": hunt_dir / "vulns/lfi_params.txt"
    }

    vulns_count = 0
    for key, filepath in vuln_files.items():
        db["vulnerabilities"][key] = []
        lines = read_lines_safe(filepath)
        unique_urls = list(set(lines))
        db["vulnerabilities"][key] = unique_urls
        vulns_count += len(unique_urls)

    db["stats"]["vulns"] = vulns_count

    # 6. Parse Extra Summary stats
    takeover_results = read_json_lines_safe(data_dir / "takeover_results.json")
    db["stats"]["takeovers"] = len(takeover_results)

    waf_file = data_dir / "waf_detect.txt"
    db["stats"]["wafs"] = len(read_lines_safe(waf_file))

    juicy_file = data_dir / "juicy.urls"
    db["stats"]["juicy_endpoints"] = len(read_lines_safe(juicy_file))

    js_file = data_dir / "js.urls"
    db["stats"]["js_files"] = len(read_lines_safe(js_file))

    # Read template and build output
    script_dir = Path(__file__).parent
    template_path = script_dir / "dashboard_template.html"
    
    if not template_path.exists():
        print(f"[-] Error: Template not found at {template_path}")
        sys.exit(1)

    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Inject data and target string
    html_content = html_content.replace("{TARGET}", target)
    html_content = html_content.replace("{DATA_PLACEHOLDER}", json.dumps(db, indent=2))

    output_path = hunt_dir / "dashboard.html"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[+] Web Dashboard compiled successfully: {output_path}")

if __name__ == "__main__":
    main()
