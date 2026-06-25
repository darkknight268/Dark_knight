#!/bin/bash
# Bug Hunter - Analyze Existing Data
# Usage: ./analyze.sh <target> <subs_file> <endpoints_file> <js_files_dir>
#
# Example:
#   ./analyze.sh example.com /path/to/subs.txt /path/to/endpoints.txt /path/to/js/

set -e

TARGET=$1
SUBS_FILE=$2
ENDPOINTS_FILE=$3
JS_DIR=$4
OUTPUT_DIR="/tmp/bug-hunter-$TARGET"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [subs_file] [endpoints_file] [js_dir]"
    echo ""
    echo "Examples:"
    echo "  $0 example.com                    # Interactive mode"
    echo "  $0 example.com subs.txt          # With subdomains"
    echo "  $0 example.com subs.txt endpoints.txt"
    echo "  $0 example.com subs.txt endpoints.txt js/"
    exit 1
fi

# Interactive mode - look for common data locations
if [ -z "$SUBS_FILE" ]; then
    echo "[*] No data provided, looking for existing data..."

    # Look in common locations
    for dir in /tmp/bug-hunter-$TARGET /home/Dark-Knight/subs /home/Dark-Knight/work; do
        if [ -d "$dir" ]; then
            echo "[*] Checking: $dir"
        fi
    done

    echo ""
    echo "Please provide paths to your data files:"
    echo "  - Subsdomains file"
    echo "  - Endpoints/URLs file (optional)"
    echo "  - JS files directory (optional)"
    exit 1
fi

echo "[*] Starting bug hunter analysis for: $TARGET"
echo "[*] Data source: $SUBS_FILE"

# Create output directory
mkdir -p "$OUTPUT_DIR/analysis"

# Create symlinks to data for easy access
if [ -f "$SUBS_FILE" ]; then
    ln -sf "$(realpath $SUBS_FILE)" "$OUTPUT_DIR/analysis/subs.txt"
    echo "[+] Linked subdomains: $(wc -l < "$SUBS_FILE")"
fi

if [ -f "$ENDPOINTS_FILE" ]; then
    ln -sf "$(realpath $ENDPOINTS_FILE)" "$OUTPUT_DIR/analysis/endpoints.txt"
    echo "[+] Linked endpoints: $(wc -l < "$ENDPOINTS_FILE")"
fi

if [ -d "$JS_DIR" ]; then
    ln -sf "$(realpath $JS_DIR)" "$OUTPUT_DIR/analysis/js"
    echo "[+] Linked JS files: $(ls "$JS_DIR" 2>/dev/null | wc -l)"
fi

echo ""
echo "[*] Data loaded. Now run the analysis modules:"
echo ""
echo "=== JS ANALYSIS (JSMAX) ==="
echo "cd $OUTPUT_DIR/analysis/js && analyze JS files for secrets"
echo ""
echo "=== ENDPOINT ANALYSIS ==="
echo "Review endpoints.txt for:"
echo "  - /api/* endpoints"
echo "  - /admin/*, /dashboard/*"
echo "  - /graphql, /graphql-console"
echo "  - /login, /auth/*"
echo "  - File upload endpoints"
echo ""
echo "=== SUBDOMAIN ANALYSIS ==="
echo "Review subs.txt for:"
echo "  - dev.*, staging.*, test.*"
echo "  - admin.*, panel.*"
echo "  - api.*, internal.*"
echo ""

echo "[*] Analysis setup complete"
echo "[*] Output: $OUTPUT_DIR/analysis/"