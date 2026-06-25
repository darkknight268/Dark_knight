#!/bin/bash
# Bug Hunter - Full Hunt on Existing Data
# Usage: ./hunt.sh <target> [data_dir]
#
# This script runs comprehensive bug hunting on your pre-collected data

set -e

TARGET=$1
DATA_DIR=${2:-/tmp/bug-hunter-$TARGET}

# Colors
R="\033[31m" G="\033[32m" Y="\033[33m" B="\033[34m" C="\033[36m"
W="\033[1;37m" D="\033[2m" O="\033[0m"

draw_progress() {
  local current=$1
  local total=$2
  local width=22
  local filled=$(( current * width / total ))
  local empty=$(( width - filled ))
  
  local bar=""
  for ((i=0; i<filled; i++)); do bar="${bar}█"; done
  for ((i=0; i<empty; i++)); do bar="${bar}░"; done
  
  local percent=$(( current * 100 / total ))
  echo -e "  ${D}[${G}${bar}${D}] ${W}${percent}%${O}"
}

phase_header() {
  local num=$1 title=$2
  echo -e ""
  echo -e "  ${C}✦${O} ${W}PHASE $num/4${O} ${D}⬡${O} ${C}$title${O}"
  draw_progress "$num" "4"
  echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
}



if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [data_dir]"
    echo ""
    echo "Example:"
    echo "  $0 example.com /path/to/data"
    exit 1
fi

echo -e ""
echo -e "  ${C}⚡ ${W}BUG HUNTER${O} ${D}│${O} ${B}HUNTING SESSION${O}"
echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
echo -e "  ${D}Target:${O}     ${W}$TARGET${O}"
echo -e "  ${D}Workspace:${O}  ${C}$DATA_DIR${O}"
echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
echo -e ""


# Setup output
HUNT_DIR="$DATA_DIR/hunt-results"
mkdir -p "$HUNT_DIR"/{js-analysis,endpoints,vulns,secrets,takeover}


# ===== 1. JS ANALYSIS (JSMAX) =====
phase_header 1 "JS ANALYSIS (JSMAX)"

# Find JS files
JS_FILES=$(find "$DATA_DIR" -type f -name "*.js" 2>/dev/null | head -100)
if [ -n "$JS_FILES" ]; then
    echo "[*] Found JS files to analyze"

    for JS_FILE in $JS_FILES; do
        echo "    [*] Analyzing: $(basename $JS_FILE)"

        # Check for secrets using grep patterns
        BASENAME=$(basename "$JS_FILE")

        # AWS Keys
        grep -hE "(AKIA|ASIA)[0-9A-Z]{16}" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/aws_keys.txt" || true

        # Azure Keys
        grep -hE "(DefaultEndpointsProtocol=https|BlobEndpoint|AccountName=)" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/azure.txt" || true

        # GCP Keys
        grep -hE "(AIza[0-9A-Za-z\\-_]{35})" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/gcp.txt" || true

        # JWT Tokens
        grep -hE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/jwt.txt" || true

        # API Keys (generic)
        grep -hE "(api[_-]?key|apikey|API[_-]?KEY)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{20,}" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/api_keys.txt" || true

        # Hardcoded Passwords
        grep -hE "(password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^&]{4,}" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/passwords.txt" || true

        # Internal Endpoints
        grep -hE "(https?://)[^\"'<>]+(internal|admin|api|dev|staging)" "$JS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/internal_endpoints.txt" || true

        # S3 Buckets
        grep -hE "[a-z0-9\-\.]+\.s3\.amazonaws\.com" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/s3_buckets.txt" || true

        # Firebase URLs
        grep -hE "firebaseio\.com|firebasestorage\.googleapis\.com" "$JS_FILE" 2>/dev/null >> "$HUNT_DIR/secrets/firebase.txt" || true
    done

    echo "[+] JS Analysis complete"
else
    echo "[*] No JS files found in data directory"
fi

# ===== 2. ENDPOINT ANALYSIS =====
phase_header 2 "ENDPOINT ANALYSIS"

# Find all URLs/endpoints (excluding results)
URLS_FILE=$(find "$DATA_DIR" -not -path "*/hunt-results/*" -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null | xargs grep -l "http" 2>/dev/null | head -1)


if [ -f "$URLS_FILE" ]; then
    echo "[*] Found URL data: $URLS_FILE"

    # API Endpoints
    grep -hE "/api/|/graphql|/rest/|/v[0-9]+/" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/api.txt" || true

    # Admin Panels
    grep -hE "/admin|/dashboard|/panel|/manage|/cms" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/admin.txt" || true

    # Auth Endpoints
    grep -hE "/login|/auth|/register|/signup|/logout|/password|/reset" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/auth.txt" || true

    # File Upload
    grep -hE "/upload|/file|/image|/avatar|/document|/media" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/upload.txt" || true

    # Sensitive Files
    grep -hE "\.(env|json|xml|config|conf|ini|yml|yaml|bak|swp|sql|gz|zip|tar|log)$" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/sensitive.txt" || true

    # IDOR Patterns (numeric IDs)
    grep -hE "/[0-9]+|/user/[0-9]+|/id/[0-9]+|/order/[0-9]+" "$URLS_FILE" 2>/dev/null | sort -u >> "$HUNT_DIR/endpoints/idor_patterns.txt" || true

    echo "[+] Endpoint Analysis complete"
fi

# ===== 3. SUBDOMAIN ANALYSIS =====
phase_header 3 "SUBDOMAIN ANALYSIS"

SUBS_FILE=$(find "$DATA_DIR" -type f -name "subs*.txt" -o -name "*domains*" 2>/dev/null | head -1)

if [ -f "$SUBS_FILE" ]; then
    echo "[*] Found subdomains: $SUBS_FILE"

    # Dev/Test/Staging
    grep -hE "^(dev|staging|test|qa|uat)\." "$SUBS_FILE" 2>/dev/null >> "$HUNT_DIR/takeover/dev_staging.txt" || true

    # Internal names
    grep -hE "(internal|private|intranet|local|corp)" "$SUBS_FILE" 2>/dev/null >> "$HUNT_DIR/takeover/internal.txt" || true

    # Admin panels
    grep -hE "^(admin|panel|control|cms|manage)" "$SUBS_FILE" 2>/dev/null >> "$HUNT_DIR/takeover/admin_subs.txt" || true

    # Cloud services (potential takeover)
    grep -hE "\.(s3|cloudfront|herokuapp|azurewebsites|googleusercontent|github\.io)" "$SUBS_FILE" 2>/dev/null >> "$HUNT_DIR/takeover/cloud.txt" || true

    echo "[+] Subdomain Analysis complete"
fi

# ===== 4. VULNERABILITY INDICATORS =====
phase_header 4 "VULNERABILITY INDICATORS"

# Check for common vuln patterns in URLs
if [ -f "$URLS_FILE" ]; then
    # XSS Indicators
    grep -hE "(\?|q=|search=|s=|query=|keyword=|page=)[^&]*" "$URLS_FILE" 2>/dev/null | head -20 >> "$HUNT_DIR/vulns/xss_params.txt" || true

    # SQLi Indicators
    grep -hE "(id=|user=|cat=|order=|sort=|page=)[0-9]+" "$URLS_FILE" 2>/dev/null | head -20 >> "$HUNT_DIR/vulns/sqli_params.txt" || true

    # SSRF Indicators
    grep -hE "(url=|uri=|dest=|redirect=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|style=|doc=|img=|filename=|f=|u=)[^&]*" "$URLS_FILE" 2>/dev/null | head -20 >> "$HUNT_DIR/vulns/ssrf_params.txt" || true

    # LFI Indicators
    grep -hE "(file=|document=|folder=|pg=|style=|doc=|template=|include=|page=|path=|css=|js=)[^&]*" "$URLS_FILE" 2>/dev/null | head -20 >> "$HUNT_DIR/vulns/lfi_params.txt" || true

    echo "[+] Vulnerability Indicators complete"
fi

# ===== SUMMARY =====
echo -e ""
echo -e "  ${G}✔${O} ${W}HUNT COMPLETE${O}"
echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
echo -e "  ${D}Results saved to ▸${O} ${C}$HUNT_DIR/${O}"
echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
echo -e ""
echo -e "  ${C}📁 ENDPOINTS${O}"
[ -f "$HUNT_DIR/endpoints/api.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} URLs\n" "API" "$(wc -l < "$HUNT_DIR/endpoints/api.txt")"
[ -f "$HUNT_DIR/endpoints/admin.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} URLs\n" "Admin" "$(wc -l < "$HUNT_DIR/endpoints/admin.txt")"
[ -f "$HUNT_DIR/endpoints/auth.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} URLs\n" "Auth" "$(wc -l < "$HUNT_DIR/endpoints/auth.txt")"
[ -f "$HUNT_DIR/endpoints/upload.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} URLs\n" "Upload" "$(wc -l < "$HUNT_DIR/endpoints/upload.txt")"

echo -e ""
echo -e "  ${Y}🔐 SECRETS${O}"
[ -f "$HUNT_DIR/secrets/aws_keys.txt" ] && printf "     %-15s ${D}▸${O}  ${R}%s${O} matches\n" "AWS Keys" "$(wc -l < "$HUNT_DIR/secrets/aws_keys.txt")"
[ -f "$HUNT_DIR/secrets/jwt.txt" ] && printf "     %-15s ${D}▸${O}  ${Y}%s${O} matches\n" "JWT Tokens" "$(wc -l < "$HUNT_DIR/secrets/jwt.txt")"
[ -f "$HUNT_DIR/secrets/api_keys.txt" ] && printf "     %-15s ${D}▸${O}  ${Y}%s${O} matches\n" "API Keys" "$(wc -l < "$HUNT_DIR/secrets/api_keys.txt")"
[ -f "$HUNT_DIR/secrets/s3_buckets.txt" ] && printf "     %-15s ${D}▸${O}  ${C}%s${O} matches\n" "S3 Buckets" "$(wc -l < "$HUNT_DIR/secrets/s3_buckets.txt")"

echo -e ""
echo -e "  ${R}⚡ VULN PARAMETERS${O}"
[ -f "$HUNT_DIR/vulns/xss_params.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} candidates\n" "XSS" "$(wc -l < "$HUNT_DIR/vulns/xss_params.txt")"
[ -f "$HUNT_DIR/vulns/sqli_params.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} candidates\n" "SQLi" "$(wc -l < "$HUNT_DIR/vulns/sqli_params.txt")"
[ -f "$HUNT_DIR/vulns/ssrf_params.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} candidates\n" "SSRF" "$(wc -l < "$HUNT_DIR/vulns/ssrf_params.txt")"
[ -f "$HUNT_DIR/vulns/lfi_params.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} candidates\n" "LFI" "$(wc -l < "$HUNT_DIR/vulns/lfi_params.txt")"

echo -e ""
echo -e "  ${B}🎯 SUBDOMAIN TAKEOVER${O}"
[ -f "$HUNT_DIR/takeover/dev_staging.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} targets\n" "Dev/Staging" "$(wc -l < "$HUNT_DIR/takeover/dev_staging.txt")"
[ -f "$HUNT_DIR/takeover/cloud.txt" ] && printf "     %-15s ${D}▸${O}  ${W}%s${O} targets\n" "Cloud" "$(wc -l < "$HUNT_DIR/takeover/cloud.txt")"

echo -e ""
echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${O}"
echo -e ""