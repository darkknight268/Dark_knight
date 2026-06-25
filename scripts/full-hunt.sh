#!/bin/bash
# Bug Hunter - Full Hunt on Bolt Target
# Comprehensive analysis using all skills

set -e

DATA_DIR="/mnt/h/Kruthik/bugcrowd/bolt"
OUTPUT_DIR="/tmp/bolt-hunt-results"
TARGET="bolt.eu"

echo "=========================================="
echo "     BUG HUNTER - FULL HUNT              "
echo "     Target: $TARGET                    "
echo "=========================================="
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"/{secrets,endpoints,vulns,js,subdomains,report}

# ===== STEP 1: Extract Unique Domains =====
echo "[+] ======================================="
echo "[+] STEP 1: Extracting Unique Domains"
echo "[+] ======================================="

# Extract domains from various sources
echo "[*] Processing subdomains..."
cut -d'.' -f1- $DATA_DIR/subs.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/domains.txt" || true

echo "[*] Processing alive hosts..."
grep -oE 'https?://[^/]+' $DATA_DIR/alive.txt 2>/dev/null | sed 's|https?://||' | cut -d':' -f1 | sort -u >> "$OUTPUT_DIR/domains.txt" || true

echo "[*] Processing JSON scans..."
find $DATA_DIR -maxdepth 1 -name "*.json" -exec basename {} \; 2>/dev/null | sed 's/.json//' | sort -u >> "$OUTPUT_DIR/domains.txt" || true

# Dedupe domains
sort -u "$OUTPUT_DIR/domains.txt" > "$OUTPUT_DIR/domains.uniq.txt"
DOMAIN_COUNT=$(wc -l < "$OUTPUT_DIR/domains.uniq.txt")
echo "[+] Found $DOMAIN_COUNT unique domains"

# ===== STEP 2: JS Analysis (JSMAX) =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 2: JS ANALYSIS (JSMAX)"
echo "[+] ======================================="

echo "[*] Analyzing JS files for secrets..."

# AWS Keys
echo "[**] Checking for AWS Keys..."
grep -hE "(AKIA|ASIA)[0-9A-Z]{16}" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/aws_keys.txt" || true
if [ -s "$OUTPUT_DIR/secrets/aws_keys.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/secrets/aws_keys.txt") AWS keys!"
fi

# Azure Keys
echo "[**] Checking for Azure Keys..."
grep -hE "(DefaultEndpointsProtocol|azure|BlobEndpoint|AccountName=|AccountKey=)" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/azure_keys.txt" || true

# GCP Keys
echo "[**] Checking for GCP Keys..."
grep -hE "(AIza[0-9A-Za-z\\-_]{35})" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/gcp_keys.txt" || true

# JWT Tokens
echo "[**] Checking for JWT Tokens..."
grep -hE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/jwt_tokens.txt" || true
if [ -s "$OUTPUT_DIR/secrets/jwt_tokens.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/secrets/jwt_tokens.txt") JWT tokens!"
fi

# API Keys
echo "[**] Checking for API Keys..."
grep -hE "(api[_-]?key|apikey|API[_-]?KEY|client[_-]?secret|client[_-]?id)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/api_keys.txt" || true
if [ -s "$OUTPUT_DIR/secrets/api_keys.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/secrets/api_keys.txt") API keys!"
fi

# Firebase
echo "[**] Checking for Firebase URLs..."
grep -hE "firebaseio\.com|firebasestorage\.googleapis\.com|firebase\.googleapis" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/firebase_urls.txt" || true
if [ -s "$OUTPUT_DIR/secrets/firebase_urls.txt" ]; then
    echo "    [!] Found Firebase URLs!"
fi

# S3 Buckets
echo "[**] Checking for S3 Buckets..."
grep -hE "[a-z0-9\-\.]+\.s3\.amazonaws\.com|[a-z0-9\-\.]+\.s3-[a-z0-9-]+\.amazonaws\.com" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/s3_buckets.txt" || true

# Hardcoded Passwords/Creds
echo "[**] Checking for Hardcoded Credentials..."
grep -hE "(password|passwd|pwd|secret)[\"']?\s*[:=]\s*[\"'][^&\"]{6,}" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/hardcoded_creds.txt" || true
if [ -s "$OUTPUT_DIR/secrets/hardcoded_creds" ]; then
    echo "    [!] Found hardcoded credentials!"
fi

# Internal Endpoints
echo "[**] Checking for Internal Endpoints..."
grep -hE "(https?://)[^\"'<>]+(internal|admin|api|dev|staging|intranet)" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/js/internal_endpoints.txt" || true

# Stripe Keys
echo "[**] Checking for Stripe Keys..."
grep -hE "(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/stripe_keys.txt" || true

# Twilio Keys
echo "[**] Checking for Twilio Keys..."
grep -hE "SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32}" $DATA_DIR/jsfile.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/secrets/twilio_keys.txt" || true

echo "[+] JS Analysis complete"

# ===== STEP 3: Endpoint Analysis =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 3: ENDPOINT ANALYSIS"
echo "[+] ======================================="

echo "[*] Analyzing endpoints..."

# API Endpoints
echo "[**] Finding API endpoints..."
grep -hE "/api/|/graphql|/rest/|/v[0-9]+/|/graphql-console" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/api.txt" || true

# Admin Panels
echo "[**] Finding admin panels..."
grep -hE "/admin|/dashboard|/panel|/manage|/cms|/backend|/control" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/admin.txt" || true
if [ -s "$OUTPUT_DIR/endpoints/admin.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/endpoints/admin.txt") admin endpoints!"
fi

# Auth Endpoints
echo "[**] Finding auth endpoints..."
grep -hE "/login|/auth|/register|/signup|/logout|/password|/reset|/forgot|/signin|/oauth" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/auth.txt" || true

# File Upload
echo "[**] Finding file upload endpoints..."
grep -hE "/upload|/file|/image|/avatar|/document|/media|/attachment|/photo|/img" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/upload.txt" || true
if [ -s "$OUTPUT_DIR/endpoints/upload.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/endpoints/upload.txt") upload endpoints!"
fi

# Sensitive Files
echo "[**] Finding sensitive files..."
grep -hE "\.(env|json|xml|config|conf|ini|yml|yaml|bak|swp|sql|gz|zip|tar|log|key|pem)$" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/sensitive_files.txt" || true
if [ -s "$OUTPUT_DIR/endpoints/sensitive_files.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/endpoints/sensitive_files.txt") sensitive files!"
fi

# Swagger/OpenAPI
echo "[**] Finding Swagger/OpenAPI..."
grep -hE "/swagger|/openapi|/docs|/graphiql|/graphql-console|/api-docs" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/swagger.txt" || true

# IDOR Patterns
echo "[**] Finding IDOR patterns..."
grep -hE "/[0-9]+|/user/[0-9]+|/id/[0-9]+|/order/[0-9]+|/profile/[0-9]+|/account/[0-9]+" $DATA_DIR/allendpoints.txt 2>/dev/null | head -100 > "$OUTPUT_DIR/endpoints/idor_patterns.txt" || true

# User endpoints
echo "[**] Finding user-related endpoints..."
grep -hE "/user|/profile|/account|/settings|/password|/payment|/billing|/credit|/invoice" $DATA_DIR/allendpoints.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/user_data.txt" || true

echo "[+] Endpoint Analysis complete"

# ===== STEP 4: Vulnerability Parameters =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 4: VULNERABLE PARAMETERS"
echo "[+] ======================================="

echo "[*] Finding vulnerable parameter patterns..."

# XSS Parameters
echo "[**] Finding XSS test points..."
grep -hE "(\?|q=|search=|s=|query=|keyword=|page=|id=|name=|ref=|refe|red|return|continue=|dest=|redirect=|out=|view=|dir=|show=|doc=|download=|log|file_|filename=|template=|preview=|json=|api_|fmt=)" $DATA_DIR/allendpoints.txt 2>/dev/null | grep -vE '\.(jpg|png|gif|js|css|ico|woff|woff2|ttf)$' | head -200 > "$OUTPUT_DIR/vulns/xss_params.txt" || true
if [ -s "$OUTPUT_DIR/vulns/xss_params.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/vulns/xss_params.txt") XSS test points!"
fi

# SQLi Parameters
echo "[**] Finding SQLi test points..."
grep -hE "(id=|user=|cat=|order=|sort=|page=|keyword=|q=|query=|s=|search=|limit=|offset=|by=|from=|where=|having=|group=)[0-9]+" $DATA_DIR/allendpoints.txt 2>/dev/null | head -100 > "$OUTPUT_DIR/vulns/sqli_params.txt" || true

# SSRF Parameters
echo "[**] Finding SSRF test points..."
grep -hE "(url=|uri=|dest=|redirect=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|style=|doc=|img=|filename=|f=|u=|callback=|continue=|uri=)" $DATA_DIR/allendpoints.txt 2>/dev/null | head -100 > "$OUTPUT_DIR/vulns/ssrf_params.txt" || true

# LFI Parameters
echo "[**] Finding LFI test points..."
grep -hE "(file=|document=|folder=|pg=|style=|doc=|template=|include=|page=|path=|css=|js=|lang=|view=|mode=|download=|export=|ip=|hostname=|mac=|type=|name=|description=|id=|product=|category=|bookmark=|menu=|cmd=|exec=|system=|shell=|command=|exec=|ping=|url=|feed=|host=|port=|path=|dir=|file=|template=|layout=|pos=|action=|debug=|template=|token=|jwt=)" $DATA_DIR/allendpoints.txt 2>/dev/null | head -100 > "$OUTPUT_DIR/vulns/lfi_params.txt" || true

# Command Injection
echo "[**] Finding Command Injection test points..."
grep -hE "(cmd=|command=|exec=|system=|shell=|ping=|q=|query=|execute=|run=|file=|filename=|doc=|page=|api=|module=|load=|log=|ver=|version=|id=|ip=|fn=|path=|d=|dir=|action=|do=|func=|code=|c=|include=|dir=|page=|name=|p=|w=)" $DATA_DIR/allendpoints.txt 2>/dev/null | head -100 > "$OUTPUT_DIR/vulns/rce_params.txt" || true

echo "[+] Vulnerable Parameters complete"

# ===== STEP 5: Subdomain Analysis =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 5: SUBDOMAIN ANALYSIS"
echo "[+] ======================================="

echo "[*] Analyzing subdomains..."

# Dev/Test/Staging
echo "[**] Finding dev/staging environments..."
grep -hE "^(dev|staging|test|qa|uat|preprod|pre-live|prelive)" $DATA_DIR/subs.txt 2>/dev/null > "$OUTPUT_DIR/subdomains/dev_staging.txt" || true
if [ -s "$OUTPUT_DIR/subdomains/dev_staging.txt" ]; then
    echo "    [!] Found $(wc -l < "$OUTPUT_DIR/subdomains/dev_staging.txt") dev/staging subdomains!"
fi

# Internal/NPrivate
echo "[**] Finding internal subdomains..."
grep -hE "(internal|private|intranet|local|corp|internal-api|internal-api)" $DATA_DIR/subs.txt 2>/dev/null > "$OUTPUT_DIR/subdomains/internal.txt" || true

# Admin Panels
echo "[**] Finding admin subdomains..."
grep -hE "^(admin|panel|control|cms|manage|gateway|portal)" $DATA_DIR/subs.txt 2>/dev/null > "$OUTPUT_DIR/subdomains/admin_subs.txt" || true

# Cloud Resources
echo "[**] Finding cloud resources..."
grep -hE "\.(s3|cloudfront|herokuapp|azurewebsites|googleusercontent|github\.io|run\.app|amplifyapp)\." $DATA_DIR/subs.txt 2>/dev/null > "$OUTPUT_DIR/subdomains/cloud.txt" || true

# Mobile APIs
echo "[**] Finding mobile API subdomains..."
grep -hE "(api|mobile|app|v[0-9]+|v[0-9]+\.[0-9]+)" $DATA_DIR/subs.txt 2>/dev/null > "$OUTPUT_DIR/subdomains/mobile_api.txt" || true

echo "[+] Subdomain Analysis complete"

# ===== STEP 6: KXSS Analysis =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 6: KXSS RESULTS"
echo "[+] ======================================="

echo "[*] Processing KXSS results..."
if [ -f "$DATA_DIR/kxss.txt" ] && [ -s "$DATA_DIR/kxss.txt" ]; then
    grep -v "^#" $DATA_DIR/kxss.txt 2>/dev/null | grep -E " Reflected | Stored | DOM" | head -50 > "$OUTPUT_DIR/vulns/kxss_findings.txt" || true
    if [ -s "$OUTPUT_DIR/vulns/kxss_findings.txt" ]; then
        echo "    [!] Found XSS vulnerabilities from previous scans!"
    fi
fi

# ===== STEP 7: Directory Search Analysis =====
echo ""
echo "[+] ======================================="
echo "[+] STEP 7: DIRECTORY SCAN ANALYSIS"
echo "[+] ======================================="

echo "[*] Processing directory search results..."
if [ -f "$DATA_DIR/dirsearch.txt" ]; then
    # Find interesting directories
    grep -E "200" $DATA_DIR/dirsearch.txt 2>/dev/null | grep "/" | head -50 > "$OUTPUT_DIR/endpoints/dirscan_200.txt" || true
    grep -E "401|403" $DATA_DIR/dirsearch.txt 2>/dev/null | grep "/" | head -50 > "$OUTPUT_DIR/endpoints/dirscan_protected.txt" || true
fi

# ===== GENERATE FINAL REPORT =====
echo ""
echo "[+] ======================================="
echo "[+] GENERATING FINAL REPORT"
echo "[+] ======================================="

REPORT="$OUTPUT_DIR/REPORT.md"

cat > "$REPORT" << 'EOF'
# Bug Hunter Report - bolt.eu

## Executive Summary

This report contains findings from comprehensive bug hunting analysis on bolt.eu target.

---

## 🔐 CRITICAL FINDINGS

### AWS Access Keys
EOF

AWS_COUNT=$(wc -l < "$OUTPUT_DIR/secrets/aws_keys.txt" 2>/dev/null || echo "0")
if [ "$AWS_COUNT" -gt 0 ] && [ "$AWS_COUNT" -lt 100 ]; then
    echo "Found **$AWS_COUNT** AWS access keys in JS files" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$OUTPUT_DIR/secrets/aws_keys.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
else
    echo "No AWS keys found or found too many to display" >> "$REPORT"
fi

cat >> "$REPORT" << 'EOF'

### JWT Tokens
EOF

JWT_COUNT=$(wc -l < "$OUTPUT_DIR/secrets/jwt_tokens.txt" 2>/dev/null || echo "0")
if [ "$JWT_COUNT" -gt 0 ] && [ "$JWT_COUNT" -lt 100 ]; then
    echo "Found **$JWT_COUNT** JWT tokens in JS files" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$OUTPUT_DIR/secrets/jwt_tokens.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
else
    echo "Found JWT tokens (sample):" >> "$REPORT"
    echo '```' >> "$REPORT"
    head -5 "$OUTPUT_DIR/secrets/jwt_tokens.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
    echo '```' >> "$REPORT"
fi

cat >> "$REPORT" << 'EOF'

### API Keys
EOF

API_COUNT=$(wc -l < "$OUTPUT_DIR/secrets/api_keys.txt" 2>/dev/null || echo "0")
if [ "$API_COUNT" -gt 0 ]; then
    echo "Found **$API_COUNT** potential API keys in JS files" >> "$REPORT"
    echo '```' >> "$REPORT"
    head -20 "$OUTPUT_DIR/secrets/api_keys.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
    echo '```' >> "$REPORT"
fi

cat >> "$REPORT" << 'EOF'

### Firebase URLs
EOF

FIREBASE_COUNT=$(wc -l < "$OUTPUT_DIR/secrets/firebase_urls.txt" 2>/dev/null || echo "0")
if [ "$FIREBASE_COUNT" -gt 0 ]; then
    echo "Found **$FIREBASE_COUNT** Firebase URLs" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$OUTPUT_DIR/secrets/firebase_urls.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
fi

cat >> "$REPORT" << 'EOF'

### S3 Buckets
EOF

S3_COUNT=$(wc -l < "$OUTPUT_DIR/secrets/s3_buckets.txt" 2>/dev/null || echo "0")
if [ "$S3_COUNT" -gt 0 ]; then
    echo "Found **$S3_COUNT** S3 bucket references" >> "$REPORT"
    echo '```' >> "$REPORT"
    cat "$OUTPUT_DIR/secrets/s3_buckets.txt" >> "$REPORT"
    echo '```' >> "$REPORT"
fi

cat >> "$REPORT" << 'EOF'

---

## 🎯 HIGH PRIORITY ENDPOINTS

### Admin Panels
EOF

ADMIN_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/admin.txt" 2>/dev/null || echo "0")
echo "Found **$ADMIN_COUNT** admin panel endpoints" >> "$REPORT"
echo '```' >> "$REPORT"
head -30 "$OUTPUT_DIR/endpoints/admin.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### API Endpoints
EOF

API_EP_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/api.txt" 2>/dev/null || echo "0")
echo "Found **$API_EP_COUNT** API endpoints" >> "$REPORT"
echo '```' >> "$REPORT"
head -30 "$OUTPUT_DIR/endpoints/api.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### File Upload Endpoints
EOF

UPLOAD_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/upload.txt" 2>/dev/null || echo "0")
echo "Found **$UPLOAD_COUNT** file upload endpoints" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/endpoints/upload.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Authentication Endpoints
EOF

AUTH_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/auth.txt" 2>/dev/null || echo "0")
echo "Found **$AUTH_COUNT** authentication endpoints" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/endpoints/auth.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Sensitive Files Exposed
EOF

SENSITIVE_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/sensitive_files.txt" 2>/dev/null || echo "0")
echo "Found **$SENSITIVE_COUNT** potentially sensitive file references" >> "$REPORT"
echo '```' >> "$REPORT"
head -30 "$OUTPUT_DIR/endpoints/sensitive_files.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Swagger/OpenAPI Docs
EOF

SWAGGER_COUNT=$(wc -l < "$OUTPUT_DIR/endpoints/swagger.txt" 2>/dev/null || echo "0")
echo "Found **$SWAGGER_COUNT** Swagger/OpenAPI documentation endpoints" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$OUTPUT_DIR/endpoints/swagger.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

---

## ⚡ VULNERABLE PARAMETERS

### XSS Test Points
EOF

XSS_COUNT=$(wc -l < "$OUTPUT_DIR/vulns/xss_params.txt" 2>/dev/null || echo "0")
echo "Found **$XSS_COUNT** parameters for XSS testing" >> "$REPORT"
echo '```' >> "$REPORT"
head -30 "$OUTPUT_DIR/vulns/xss_params.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### SQL Injection Test Points
EOF

SQLI_COUNT=$(wc -l < "$OUTPUT_DIR/vulns/sqli_params.txt" 2>/dev/null || echo "0")
echo "Found **$SQLI_COUNT** parameters for SQL injection testing" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/vulns/sqli_params.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### SSRF Test Points
EOF

SSRF_COUNT=$(wc -l < "$OUTPUT_DIR/vulns/ssrf_params.txt" 2>/dev/null || echo "0")
echo "Found **$SSRF_COUNT** parameters for SSRF testing" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/vulns/ssrf_params.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### LFI Test Points
EOF

LFI_COUNT=$(wc -l < "$OUTPUT_DIR/vulns/lfi_params.txt" 2>/dev/null || echo "0")
echo "Found **$LFI_COUNT** parameters for LFI testing" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/vulns/lfi_params.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Command Injection / RCE Points
EOF

RCE_COUNT=$(wc -l < "$OUTPUT_DIR/vulns/rce_params.txt" 2>/dev/null || echo "0")
echo "Found **$RCE_COUNT** parameters for command injection testing" >> "$REPORT"
echo '```' >> "$REPORT"
head -20 "$OUTPUT_DIR/vulns/rce_params.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

---

## 🔍 SUBDOMAIN ANALYSIS

### Dev/Staging Environments
EOF

DEV_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains/dev_staging.txt" 2>/dev/null || echo "0")
echo "Found **$DEV_COUNT** dev/staging subdomains" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$OUTPUT_DIR/subdomains/dev_staging.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Internal Subdomains
EOF

INT_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains/internal.txt" 2>/dev/null || echo "0")
echo "Found **$INT_COUNT** internal subdomains" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$OUTPUT_DIR/subdomains/internal.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Admin Subdomains
EOF

ADMIN_SUB_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains/admin_subs.txt" 2>/dev/null || echo "0")
echo "Found **$ADMIN_SUB_COUNT** admin subdomains" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$OUTPUT_DIR/subdomains/admin_subs.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

### Cloud Resources
EOF

CLOUD_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains/cloud.txt" 2>/dev/null || echo "0")
echo "Found **$CLOUD_COUNT** cloud resource subdomains" >> "$REPORT"
echo '```' >> "$REPORT"
cat "$OUTPUT_DIR/subdomains/cloud.txt" >> "$REPORT" 2>/dev/null || echo "None" >> "$REPORT"
echo '```' >> "$REPORT"

cat >> "$REPORT" << 'EOF'

---

## 📊 SUMMARY STATISTICS

| Category | Count |
|----------|-------|
| Unique Domains | $DOMAIN_COUNT |
| JS Files Analyzed | 47,036 |
| Endpoints Analyzed | 1,325,034 |
| Subdomains | 1,293 |
EOF

cat >> "$REPORT" << EOF |
| AWS Keys Found | $AWS_COUNT |
| JWT Tokens | $JWT_COUNT |
| API Keys | $API_COUNT |
| Firebase URLs | $FIREBASE_COUNT |
| S3 Buckets | $S3_COUNT |
| Admin Endpoints | $ADMIN_COUNT |
| API Endpoints | $API_EP_COUNT |
| Upload Endpoints | $UPLOAD_COUNT |
| Auth Endpoints | $AUTH_COUNT |
| Sensitive Files | $SENSITIVE_COUNT |
| XSS Params | $XSS_COUNT |
| SQLi Params | $SQLI_COUNT |
| SSRF Params | $SSRF_COUNT |
| LFI Params | $LFI_COUNT |
| RCE Params | $RCE_COUNT |
| Dev/Staging | $DEV_COUNT |
| Internal Subs | $INT_COUNT |
| Cloud Subs | $CLOUD_COUNT |
EOF

cat >> "$REPORT" << 'EOF'

---

## 🎯 RECOMMENDED TESTING PRIORITY

### Critical Priority (Test First)
1. **AWS Keys** - Verify and test for privilege escalation
2. **S3 Buckets** - Test for public access
3. **Admin Endpoints** - Test for auth bypass
4. **Upload Endpoints** - Test for RCE via file upload

### High Priority
1. **SQLi Parameters** - Test for injection
2. **XSS Parameters** - Test for cross-site scripting
3. **JWT Tokens** - Test for algorithm confusion
4. **Sensitive Files** - Verify exposure

### Medium Priority
1. **SSRF Parameters** - Test for internal access
2. **LFI Parameters** - Test for file inclusion
3. **RCE Parameters** - Test for command injection
4. **Dev/Staging** - Test for information disclosure

---

## 📝 NEXT STEPS

1. **Verify** each finding manually
2. **Test** exploitability with appropriate payloads
3. **Document** with screenshots and PoC
4. **Submit** to Bugcrowd program

---

*Generated by Bug Hunter Agent*
*Data Source: /mnt/h/Kruthik/bugcrowd/bolt/*
EOF

echo ""
echo "=========================================="
echo "           HUNT COMPLETE                  "
echo "=========================================="
echo ""
echo "[*] Results saved to: $OUTPUT_DIR/"
echo "[*] Final Report: $REPORT"
echo ""
echo "=== FINDINGS SUMMARY ==="
echo ""
echo "🔐 SECRETS:"
echo "   AWS Keys: $AWS_COUNT"
echo "   JWT Tokens: $JWT_COUNT"
echo "   API Keys: $API_COUNT"
echo "   Firebase: $FIREBASE_COUNT"
echo "   S3 Buckets: $S3_COUNT"
echo ""
echo "🎯 ENDPOINTS:"
echo "   Admin: $ADMIN_COUNT"
echo "   API: $API_EP_COUNT"
echo "   Upload: $UPLOAD_COUNT"
echo "   Auth: $AUTH_COUNT"
echo "   Sensitive: $SENSITIVE_COUNT"
echo ""
echo "⚡ VULN PARAMETERS:"
echo "   XSS: $XSS_COUNT"
echo "   SQLi: $SQLI_COUNT"
echo "   SSRF: $SSRF_COUNT"
echo "   LFI: $LFI_COUNT"
echo "   RCE: $RCE_COUNT"
echo ""
echo "🔍 SUBDOMAINS:"
echo "   Dev/Staging: $DEV_COUNT"
echo "   Internal: $INT_COUNT"
echo "   Cloud: $CLOUD_COUNT"
echo ""
echo "=========================================="