#!/bin/bash
# Bug Hunter - Full Hunt on Existing Data
# Usage: ./hunt.sh <target> [data_dir]
#
# This script runs comprehensive bug hunting on your pre-collected data

set -e

TARGET=$1
DATA_DIR=${2:-/tmp/bug-hunter-$TARGET}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [data_dir]"
    echo ""
    echo "Example:"
    echo "  $0 example.com /path/to/data"
    exit 1
fi

echo "=========================================="
echo "     BUG HUNTER - HUNTING SESSION        "
echo "=========================================="
echo "[*] Target: $TARGET"
echo "[*] Data: $DATA_DIR"
echo ""

# Setup output
HUNT_DIR="$DATA_DIR/hunt-results"
mkdir -p "$HUNT_DIR"/{js-analysis,endpoints,vulns,secrets, takeover}

# ===== 1. JS ANALYSIS (JSMAX) =====
echo "[+] ======================================="
echo "[+] PHASE 1: JS ANALYSIS (JSMAX)"
echo "[+] ======================================="

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
echo "[+] ======================================="
echo "[+] PHASE 2: ENDPOINT ANALYSIS"
echo "[+] ======================================="

# Find all URLs/endpoints
URLS_FILE=$(find "$DATA_DIR" -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null | xargs grep -l "http" 2>/dev/null | head -1)

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
echo "[+] ======================================="
echo "[+] PHASE 3: SUBDOMAIN ANALYSIS"
echo "[+] ======================================="

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
echo "[+] ======================================="
echo "[+] PHASE 4: VULNERABILITY INDICATORS"
echo "[+] ======================================="

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
echo ""
echo "=========================================="
echo "           HUNT COMPLETE                  "
echo "=========================================="
echo ""
echo "[*] Results saved to: $HUNT_DIR/"
echo ""
echo "=== FINDINGS SUMMARY ==="

echo ""
echo "📁 ENDPOINTS:"
[ -f "$HUNT_DIR/endpoints/api.txt" ] && echo "   API: $(wc -l < "$HUNT_DIR/endpoints/api.txt") endpoints"
[ -f "$HUNT_DIR/endpoints/admin.txt" ] && echo "   Admin: $(wc -l < "$HUNT_DIR/endpoints/admin.txt") endpoints"
[ -f "$HUNT_DIR/endpoints/auth.txt" ] && echo "   Auth: $(wc -l < "$HUNT_DIR/endpoints/auth.txt") endpoints"
[ -f "$HUNT_DIR/endpoints/upload.txt" ] && echo "   Upload: $(wc -l < "$HUNT_DIR/endpoints/upload.txt") endpoints"

echo ""
echo "🔐 SECRETS:"
[ -f "$HUNT_DIR/secrets/aws_keys.txt" ] && echo "   AWS Keys: $(wc -l < "$HUNT_DIR/secrets/aws_keys.txt")"
[ -f "$HUNT_DIR/secrets/jwt.txt" ] && echo "   JWTs: $(wc -l < "$HUNT_DIR/secrets/jwt.txt")"
[ -f "$HUNT_DIR/secrets/api_keys.txt" ] && echo "   API Keys: $(wc -l < "$HUNT_DIR/secrets/api_keys.txt")"
[ -f "$HUNT_DIR/secrets/s3_buckets.txt" ] && echo "   S3 Buckets: $(wc -l < "$HUNT_DIR/secrets/s3_buckets.txt")"

echo ""
echo "⚡ VULN PARAMETERS:"
[ -f "$HUNT_DIR/vulns/xss_params.txt" ] && echo "   XSS: $(wc -l < "$HUNT_DIR/vulns/xss_params.txt") params"
[ -f "$HUNT_DIR/vulns/sqli_params.txt" ] && echo "   SQLi: $(wc -l < "$HUNT_DIR/vulns/sqli_params.txt") params"
[ -f "$HUNT_DIR/vulns/ssrf_params.txt" ] && echo "   SSRF: $(wc -l < "$HUNT_DIR/vulns/ssrf_params.txt") params"
[ -f "$HUNT_DIR/vulns/lfi_params.txt" ] && echo "   LFI: $(wc -l < "$HUNT_DIR/vulns/lfi_params.txt") params"

echo ""
echo "🎯 SUBDOMAIN TAKEOVER:"
[ -f "$HUNT_DIR/takeover/dev_staging.txt" ] && echo "   Dev/Staging: $(wc -l < "$HUNT_DIR/takeover/dev_staging.txt")"
[ -f "$HUNT_DIR/takeover/cloud.txt" ] && echo "   Cloud: $(wc -l < "$HUNT_DIR/takeover/cloud.txt")"

echo ""
echo "=========================================="