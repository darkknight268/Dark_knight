#!/usr/bin/env bash
set -uo pipefail

VERSION="2.0"
MAX_RETRIES=2
RETRY_DELAY=30

# Auto-load config if present
CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$CONFIG_DIR/recon.cfg" ] && source "$CONFIG_DIR/recon.cfg"
[ -f ~/.config/bug-hunter/recon.cfg ] && source ~/.config/bug-hunter/recon.cfg


# ── Dark-Knight Premium Color Palette ──
R='\033[38;5;203m'     # Red / Critical
G='\033[38;5;48m'      # Mint Green / Success
Y='\033[38;5;220m'     # Gold Yellow / Warning
C='\033[38;5;51m'      # Neon Cyan / Info
O='\033[38;5;201m'     # Magenta Purple / Accent
W='\033[1;37m'         # Bright White
D='\033[38;5;242m'     # Dark Gray / Dim
N='\033[0m'            # Reset

REQUIRED_TOOLS=(assetfinder subfinder sublist3r findomain httpx-toolkit katana hakrawler waybackurls gau gospider paramspider amass jq curl censys nmap asnmap naabu nuclei gf)
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"

check_deps() {
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "\n  ${O}✦${N} ${W}DEPENDENCY AUDIT${N} ${D}│ Checking environment...${N}"
        echo -e "  ${D}───────────────────────────────────────────────${N}"
        for tool in "${missing[@]}"; do
            case "$tool" in
                censys)
                    echo -e "  ${D}│${N}  ${C}→${N} Installing censys via pip ..."
                    pip3 install --user --break-system-packages censys 2>&1 | tail -1
                    ;;
                nmap)
                    echo -e "  ${D}│${N}  ${C}→${N} Installing nmap via apt ..."
                    sudo apt-get install -y nmap 2>&1 | tail -1
                    ;;
                asnmap)
                    echo -e "  ${D}│${N}  ${C}→${N} Installing asnmap via go ..."
                    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>&1 | tail -1
                    ;;
                *)
                    printf "  ${D}│${N}  ${R}✗ ${W}%-15s${N} ${D}Install manually${N}\n" "$tool"
                    ;;
            esac
        done
        # Re-check after install attempts
        local still_missing=()
        for tool in "${REQUIRED_TOOLS[@]}"; do
            command -v "$tool" &>/dev/null || still_missing+=("$tool")
        done
        if [[ ${#still_missing[@]} -gt 0 ]]; then
            echo -e "\n  ${R}✗${N} ${W}Build aborted. Missing requirements: ${R}${still_missing[*]}${N}"
            echo -e "  ${D}───────────────────────────────────────────────${N}\n"
            exit 1
        fi
    fi
}

get_vt_key() {
    local cfg="$HOME/.config/subfinder/provider-config.yaml"
    if [[ -f "$cfg" ]]; then
        grep -i 'virustotal' "$cfg" | awk -F': ' '{print $2}' | /usr/bin/tr -d '[]' | head -1
    fi
}

get_rh_key() {
    echo "${REDHUNT_API_KEY:-}"
}

save_state() {
    local dir="$1" phase="$2"
    mkdir -p "$dir"
    printf "PHASE=%s\nSTATUS=running\nTS=%s\n" "$phase" "$(date +%s)" > "$dir/.hunt_state"
}

read_phase() {
    local dir="$1"
    local f="$dir/.hunt_state"
    if [[ -f "$f" ]]; then
        local phase; phase=$(grep -oP 'PHASE=\K.*' "$f" 2>/dev/null) && echo "$phase" || echo "start"
    else
        echo "start"
    fi
}

DASHBOARD_TEMPLATE="$HOME/.local/share/hunt/dashboard_template.html"

dashboard_init() {
    local domain="$1" sd="$2"
    local html="$sd/dashboard.html"
    [[ ! -f "$DASHBOARD_TEMPLATE" ]] && return 1

    local json
    json=$(jq -n \
      --arg target "$domain" \
      --arg ts "$(date '+%Y-%m-%d %H:%M:%S')" \
      '{
        target: $target,
        generated_at: $ts,
        stats: {subdomains:0,live_hosts:0,open_ports:0,endpoints:0,secrets:0,vulns:0,takeovers:0,wafs:0,juicy_endpoints:0,js_files:0},
        subdomains: [], endpoints: [], secrets: {}, vulnerabilities: {}
      }')
    local safe; safe=$(echo "$json" | sed 's/[&\\]/\\&/g')
    sed "s|{DATA_PLACEHOLDER}|$safe|" "$DASHBOARD_TEMPLATE" > "$html"
}

dashboard_update() {
    local sd="$1" domain="$2"
    local html="$sd/dashboard.html"
    [[ ! -f "$DASHBOARD_TEMPLATE" ]] && return 1

    local s=$(wc -l < "$sd/subs.txt" 2>/dev/null || echo 0)
    local l=$(wc -l < "$sd/alive.txt" 2>/dev/null || echo 0)
    local p=$(wc -l < "$sd/raw/naabu.txt" 2>/dev/null || echo 0)
    local e=$(wc -l < "$sd/allendpoints.txt" 2>/dev/null || echo 0)
    local jf=$(wc -l < "$sd/jsfile.txt" 2>/dev/null || echo 0)
    local sec=$(cat "$sd/js_hunt/deepscan.txt" "$sd/js_hunt/gitleaks.txt" 2>/dev/null | wc -l || echo 0)
    local v=0
    for f in "$sd/raw/bugs"/*.txt; do
        [[ -f "$f" ]] && v=$((v + $(wc -l < "$f")))
    done
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

    local json
    json=$(jq -n \
      --arg target "$domain" \
      --arg ts "$ts" \
      --argjson s "$s" \
      --argjson l "$l" \
      --argjson p "$p" \
      --argjson e "$e" \
      --argjson jf "$jf" \
      --argjson sec "$sec" \
      --argjson v "$v" \
      '{
        target: $target,
        generated_at: $ts,
        stats: {subdomains:$s,live_hosts:$l,open_ports:$p,endpoints:$e,secrets:$sec,vulns:$v,takeovers:0,wafs:0,juicy_endpoints:0,js_files:$jf},
        subdomains: [], endpoints: [], secrets: {}, vulnerabilities: {}
      }')

    if [[ -s "$sd/probe.json" ]]; then
        local subs_json
        subs_json=$(jq -c -s '[group_by(.input)[] | first | {domain: .input, status: (."status-code" // null), ips: (.host // ""), tech: (.tech // [])}]' "$sd/probe.json" 2>/dev/null || echo "[]")
        if [[ "$subs_json" != "[]" ]]; then
            json=$(echo "$json" | jq --argjson arr "$subs_json" '.subdomains = $arr')
        fi
    fi

    if [[ -s "$sd/allendpoints.txt" ]]; then
        local tmp_eps; tmp_eps=$(mktemp)
        head -500 "$sd/allendpoints.txt" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local cat="other"
            [[ "$url" == */api/* ]] && cat="api"
            [[ "$url" == */admin* ]] && cat="admin"
            [[ "$url" == */auth* || "$url" == */login* || "$url" == */signin* || "$url" == */oauth* ]] && cat="auth"
            [[ "$url" == */upload* ]] && cat="upload"
            [[ "$url" == *.env || "$url" == *.sql || "$url" == *.bak || "$url" == *.config || "$url" == *.xml || "$url" == *.json || "$url" == *.yml || "$url" == *.yaml ]] && cat="sensitive"
            jq -n -c --arg url "$url" --arg cat "$cat" '{url: $url, category: $cat}' 2>/dev/null
        done > "$tmp_eps"
        if [[ -s "$tmp_eps" ]]; then
            local eps_json; eps_json=$(jq -s '.' "$tmp_eps" 2>/dev/null || echo "[]")
            json=$(echo "$json" | jq --argjson arr "$eps_json" '.endpoints = $arr')
        fi
        rm -f "$tmp_eps"
    fi

    local safe; safe=$(echo "$json" | sed 's/[&\\]/\\&/g')
    sed "s|{DATA_PLACEHOLDER}|$safe|" "$DASHBOARD_TEMPLATE" > "$html"
}

dashboard_open() {
    local html="$1/dashboard.html"
    [[ ! -f "$html" ]] && return
    if command -v xdg-open &>/dev/null; then
        xdg-open "$html" &>/dev/null &
    elif command -v sensible-browser &>/dev/null; then
        sensible-browser "$html" &>/dev/null &
    elif command -v firefox &>/dev/null; then
        firefox "$html" &>/dev/null &
    elif command -v google-chrome &>/dev/null; then
        google-chrome "$html" &>/dev/null &
    fi
}

draw_progress() {
    local current="$1"
    local total="$2"
    local width=25
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    
    local filled_bar=""
    local empty_bar=""
    for ((i=0; i<filled; i++)); do filled_bar="${filled_bar}━"; done
    for ((i=0; i<empty; i++)); do empty_bar="${empty_bar}┄"; done
    
    local percent=$(( current * 100 / total ))
    echo -e "  ${D}▕${C}${filled_bar}${D}${empty_bar}▏ ${W}${percent}%%${N}"
}

phase_header() {
    local num="$1" title="$2"
    printf -v num "%d" "$num" 2>/dev/null
    echo ""
    echo -e "  ${O}❖${N}  ${W}PHASE ${num}/${total_phases:-9}${N} ${D}▸${N} ${C}${title}${N}"
    draw_progress "$num" "${total_phases:-9}"
    echo -e "  ${D}───────────────────────────────────────────────${N}"
}

phase_sep() {
    echo -e "  ${D}───────────────────────────────────────────────${N}"
}


run_tool() {
    local name="$1" out="$2" step="$3" total="$4"; shift 4
    if [[ -f "$out" && -s "$out" ]]; then
        local cnt; cnt=$(wc -l < "$out" 2>/dev/null || echo 0)
        printf "  ${D}│${N}  ${C}⏭${N}  ${D}[%02d/%02d]${N}  %-14s  ${D}cached (${C}%d${D} records)${N}\n" "$step" "$total" "$name" "$cnt"
        return 0
    fi

    local t_start elapsed
    t_start=$(date +%s)
    printf "  ${D}│${N}  ${O}●${N}  ${D}[%02d/%02d]${N}  %-14s  ${D}active...${N}" "$step" "$total" "$name"

    timeout 300 "$@" &
    local pid=$!
    local spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(($(date +%s) - t_start))
        printf "\r  ${D}│${N}  ${O}%b${N}  ${D}[%02d/%02d]${N}  %-14s  ${D}active (${C}%ds${D})${N}" "${spin[$i]}" "$step" "$total" "$name" "$elapsed"
        i=$(( (i + 1) % 10 ))
        sleep 0.1
    done

    wait "$pid"
    local rc=$?
    elapsed=$(($(date +%s) - t_start))
    local count=0
    [[ -f "$out" ]] && count=$(wc -l < "$out" 2>/dev/null || echo 0)

    if [[ $rc -eq 0 && "$count" -gt 0 ]]; then
        printf "\r  ${D}│${N}  ${G}✔${N}  ${D}[%02d/%02d]${N}  %-14s  ${G}%-5d${N} ${D}found  (${C}%ds${D})${N}\n" "$step" "$total" "$name" "$count" "$elapsed"
    elif [[ $rc -eq 0 && "$count" -eq 0 ]]; then
        printf "\r  ${D}│${N}  ${C}✔${N}  ${D}[%02d/%02d]${N}  %-14s  ${D}empty  (${C}%ds${D})${N}\n" "$step" "$total" "$name" "$elapsed"
    else
        printf "\r  ${D}│${N}  ${R}✘${N}  ${D}[%02d/%02d]${N}  %-14s  ${R}failed (${C}%ds${D})${N}\n" "$step" "$total" "$name" "$elapsed"
    fi
    return $rc
}

# ── Phase 1 ──
enum_subs() {
    local domain="$1" rd="$2" sd="$3"
    phase_header "1" "Subdomain Enumeration"
    mkdir -p "$rd"; save_state "$sd" "subdomains"
    dashboard_update "$sd" 1 "Subdomain Enumeration" "running"
    local vt rhk; vt=$(get_vt_key); rhk=$(get_rh_key)
    local total=20

    run_tool "assetfinder" "$rd/assetfinder.txt"   1 $total bash -c "assetfinder --subs-only '$domain' > '$rd/assetfinder.txt' 2>/dev/null"
    run_tool "subfinder"   "$rd/subfinder.txt"     2 $total bash -c "subfinder -d '$domain' -all -silent > '$rd/subfinder.txt' 2>/dev/null"
    run_tool "sublist3r"   "$rd/sublist3r.txt"     3 $total bash -c "sublist3r -d '$domain' -o '$rd/sublist3r.txt' >/dev/null 2>&1"
    run_tool "findomain"   "$rd/findomain.txt"     4 $total bash -c "findomain -t '$domain' -q > '$rd/findomain.txt' 2>/dev/null"
    run_tool "crtsh"       "$rd/crtsh.txt"         5 $total bash -c "curl -s 'https://crt.sh/?q=%25.$domain&output=json' | jq -r '.[].name_value // empty' 2>/dev/null > '$rd/crtsh.txt'"
    run_tool "amass"       "$rd/amass.txt"         6 $total bash -c "amass enum -passive -d '$domain' -nocolor -o '$rd/amass.txt' >/dev/null 2>&1"
    run_tool "bufferover"  "$rd/bufferover.txt"    7 $total bash -c "curl -s --max-time 30 'https://dns.bufferover.run/dns?q=.$domain' | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > '$rd/bufferover.txt'"
    run_tool "riddler"     "$rd/riddler.txt"       8 $total bash -c "curl -sL --max-time 30 'https://riddler.io/search/exportcsv?q=pld:$domain' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/riddler.txt'"
    run_tool "certspotter" "$rd/certspotter.txt"   9 $total bash -c "curl -sL --max-time 30 'https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[] // empty' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/certspotter.txt'"
    run_tool "archivesubs" "$rd/archivesubs.txt"  10 $total bash -c "curl -s --max-time 30 'http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey' 2>/dev/null | sed -e 's_https*://__' -e 's/\/.*//' | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/archivesubs.txt'"
    run_tool "jldc-anubis" "$rd/jldc.txt"         11 $total bash -c "curl -sL --max-time 30 'https://jldc.me/anubis/subdomains/$domain' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/jldc.txt'"
    run_tool "threatminer" "$rd/threatminer.txt"  12 $total bash -c "curl -s --max-time 30 'https://api.threatminer.org/v2/domain.php?q=$domain&rt=5' | jq -r '.results[] // empty' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/threatminer.txt'"
    run_tool "threatcrowd" "$rd/threatcrowd.txt"  13 $total bash -c "curl -s --max-time 30 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain' | jq -r '.subdomains[] // empty' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/threatcrowd.txt'"
    run_tool "hackertarget" "$rd/hackertarget.txt" 14 $total bash -c "curl -s --max-time 30 'https://api.hackertarget.com/hostsearch/?q=$domain' 2>/dev/null | cut -d',' -f1 | sort -u > '$rd/hackertarget.txt'"
    run_tool "alienvault"   "$rd/alienvault.txt"   15 $total bash -c "curl -s --max-time 30 'https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=100&page=1' 2>/dev/null | grep -o '\"hostname\": *\"[^\"]*' | sed 's/\"hostname\": \"//' | sort -u > '$rd/alienvault.txt'"
    run_tool "subdomaincntr" "$rd/subdomaincntr.txt" 16 $total bash -c "curl -s --max-time 30 'https://api.subdomain.center/?domain=$domain' 2>/dev/null | jq -r '.[] // empty' | sort -u > '$rd/subdomaincntr.txt'"
    run_tool "censys"       "$rd/censys.txt"       17 $total bash -c "censys subdomains '$domain' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/censys.txt'"
    run_tool "nmap-crtsh"   "$rd/nmapcrtsh.txt"    18 $total bash -c "nmap --script hostmap-crtsh.nse '$domain' 2>/dev/null | grep -Po '([\w.-]*\.$domain)\b' | sort -u > '$rd/nmapcrtsh.txt'"

    if [[ -n "$vt" ]]; then
        run_tool "virustotal" "$rd/virustotal.txt" 19 $total bash -c "curl -s --max-time 30 'https://www.virustotal.com/api/v3/domains/$domain/subdomains' -H 'x-apikey: $vt' | jq -r '.data[].id // empty' 2>/dev/null > '$rd/virustotal.txt'"
    else
        echo -e "  ${D}┃${N}  ${C}[19/$total]${N} ${D}⏭${N} ${D}virustotal${N}  ${D}(no API key)${N}"
    fi

    if [[ -n "$rhk" ]]; then
        run_tool "redhunt" "$rd/redhunt.txt" 20 $total bash -c "curl -s --max-time 30 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=$domain&page_size=1000' -H 'X-BLOBR-KEY: $rhk' 2>/dev/null | jq -r '.subdomains[] // empty' | sort -u > '$rd/redhunt.txt'"
    else
        echo -e "  ${D}┃${N}  ${C}[20/$total]${N} ${D}⏭${N} ${D}redhunt${N}  ${D}(no REDHUNT_API_KEY)${N}"
    fi

    wait

    cat "$rd"/*.txt 2>/dev/null | /usr/bin/tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//g; s/^\*//g' | /usr/bin/tr ',' '\n' | sed 's/^ *//;s/ *$//' | sort -u > "$sd/subs.txt"
    local cnt; cnt=$(wc -l < "$sd/subs.txt" 2>/dev/null || echo 0)

    # Juicy subdomains — resolved + filtered for high-value keywords
    echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}dnsx-juicy${N}  ${D}resolving & filtering juicy subs ...${N}"
    cat "$sd/subs.txt" | timeout 60 dnsx -silent -a -resp 2>/dev/null | grep -oE '^[^ ]+' | grep -E 'api|dev|stg|test|admin|demo|stage|pre|vpn|portal|jenkins|gitlab|jira|grafana|prometheus|kibana' > "$rd/juicysubs.txt" 2>/dev/null
    local jcnt; jcnt=$(wc -l < "$rd/juicysubs.txt" 2>/dev/null || echo 0)
    echo -e "  ${D}┃${N}  ${G}✓${N}  ${W}dnsx-juicy${N}  ${G}${jcnt}${N} ${D}juicy subs${N}"

    dashboard_update "$sd" 1 "Subdomain Enumeration" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Subdomains collected:${N} ${G}${cnt}${N} ${D}unique${N}  ${D}|  Juicy: ${G}${jcnt}${N}"
    save_state "$sd" "subdomains_done"
}

# ── Phase 2 ──
extract_ips() {
    local domain="$1" sd="$2"
    phase_header "2" "IP Extraction & Resolution"
    save_state "$sd" "ips"
    dashboard_update "$sd" 2 "IP Extraction & Resolution" "running"
    if [[ ! -s "$sd/subs.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No subdomains to resolve${N}"
        dashboard_update "$sd" 2 "IP Extraction & Resolution" "done"
        echo "" > "$sd/ips.txt"; save_state "$sd" "ips_done"; return
    fi

    local ir="$sd/raw/ips"; mkdir -p "$ir"
    local vt; vt=$(get_vt_key)
    local total=5

    run_tool "dns-resolve" "$ir/dnsx.txt" 1 $total bash -c "cat '$sd/subs.txt' | dnsx -silent -a -resp 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > '$ir/dnsx.txt'"

    if shodan info &>/dev/null; then
        run_tool "shodan-ips" "$ir/shodan.txt" 2 $total bash -c "shodan search --fields ip_str hostname:\"$domain\" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > '$ir/shodan.txt'"
    else
        echo -e "  ${D}┃${N}  ${C}[2/$total]${N} ${D}⏭${N} ${D}shodan-ips${N}  ${D}(not configured)${N}"
    fi

    if [[ -n "$vt" ]]; then
        run_tool "vt-ips" "$ir/virustotal.txt" 3 $total bash -c "curl -s --max-time 30 'https://www.virustotal.com/api/v3/domains/$domain/resolutions' -H 'x-apikey: $vt' | jq -r '.data[].attributes.ip_address // empty' 2>/dev/null | sort -u > '$ir/virustotal.txt'"
    else
        echo -e "  ${D}┃${N}  ${C}[3/$total]${N} ${D}⏭${N} ${D}vt-ips${N}  ${D}(no API key)${N}"
    fi

    local cid="${CENSYS_API_ID:-}" csec="${CENSYS_API_SECRET:-}"
    if [[ -n "$cid" && -n "$csec" ]]; then
        run_tool "censys-ips" "$ir/censys.txt" 4 $total bash -c "curl -s --max-time 30 -u '$cid:$csec' 'https://search.censys.io/api/v2/hosts/search?q=services.service_name:HTTP+AND+dns.names:$domain&per_page=100' 2>/dev/null | jq -r '(.result.hits // [])[].ip // empty' | sort -u > '$ir/censys.txt'"
    else
        echo -e "  ${D}┃${N}  ${C}[4/$total]${N} ${D}⏭${N} ${D}censys-ips${N}  ${D}(no CENSYS_API_ID/SECRET)${N}"
    fi

    run_tool "asnmap" "$ir/asnmap.txt" 5 $total bash -c "cat '$ir/dnsx.txt' 2>/dev/null | /usr/bin/tr '\n' ',' | sed 's/,$//' | xargs -I{} asnmap -silent -ip {} 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' > '$ir/asnmap.txt'"

    wait

    cat "$ir/dnsx.txt" "$ir/shodan.txt" "$ir/virustotal.txt" "$ir/censys.txt" "$ir/asnmap.txt" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > "$sd/ips.txt"
    cat "$ir/asnmap.txt" 2>/dev/null | sort -u > "$sd/cidrs.txt"

    local ipcnt; ipcnt=$(wc -l < "$sd/ips.txt" 2>/dev/null || echo 0)
    local cidrcnt; cidrcnt=$(wc -l < "$sd/cidrs.txt" 2>/dev/null || echo 0)
    dashboard_update "$sd" 2 "IP Extraction & Resolution" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Unique IPs:${N} ${G}${ipcnt}${N}  ${D}|  CIDR ranges: ${G}${cidrcnt}${N}"
    save_state "$sd" "ips_done"
}

# ── Phase 3 ──
probe_alive() {
    local domain="$1" sd="$2"
    phase_header "3" "Live Host Probing"
    save_state "$sd" "alive"
    dashboard_update "$sd" 3 "Live Host Probing" "running"
    if [[ ! -s "$sd/subs.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No subdomains to probe${N}"; echo "" > "$sd/alive.txt"
        dashboard_update "$sd" 3 "Live Host Probing" "done"
        save_state "$sd" "alive_done"; return
    fi

    local ports="80,443,3000,8080,8000,8081,8008,8888,8443,9000,9001,9090"
    local t_start elapsed
    t_start=$(date +%s)
    printf "  ${D}┃${N}  ${C}[1/1]${N} ${O}▶${N} ${W}httpx${N}  ${D}probing${N}"

    cat "$sd/subs.txt" | httpx-toolkit -ports "$ports" -threads 200 -silent -status-code -json -o "$sd/probe.json" >/dev/null 2>&1 &
    local pid=$!
    local spin=('◐' '◓' '◑' '◒')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(($(date +%s) - t_start))
        printf "\r  ${D}┃${N}  ${C}[1/1]${N} ${O}${spin[$i]}${N} ${W}httpx${N}  ${D}${elapsed}s${N}"
        i=$(( (i + 1) % 4 )); sleep 0.2
    done
    wait "$pid"
    elapsed=$(($(date +%s) - t_start))

    jq -r 'select(."status-code" != null) | .input' "$sd/probe.json" 2>/dev/null | sort -u | awk '{print "https://" $0}' > "$sd/alive.txt" || true
    local cnt; cnt=$(wc -l < "$sd/alive.txt" 2>/dev/null || echo 0)

    # Separate by status code
    local sc_dir="$sd/status_codes"
    mkdir -p "$sc_dir"
    for code in 200 201 204 301 302 303 307 308 400 401 403 404 405 410 429 500 502 503; do
      jq -r "select(.\"status-code\" == $code) | .input" "$sd/probe.json" 2>/dev/null | sort -u | awk '{print "https://" $0}' > "$sc_dir/alive${code}.txt" || true
    done

    if [[ "$cnt" -eq 0 ]]; then
        printf "\r  ${D}┃${N}  ${C}[1/1]${N} ${Y}∼${N} ${W}httpx${N}  ${Y}0${N} ${D}alive${N}  ${D}(${elapsed}s)${N}\n"
        echo -e "  ${D}┃${N}  ${Y}⚠${N}  ${Y}Retrying with more threads ...${N}"
        sleep "$RETRY_DELAY"
        t_start=$(date +%s)
        printf "  ${D}┃${N}  ${C}[1/1]${N} ${O}▶${N} ${W}httpx${N}  ${D}retry${N}"
        cat "$sd/subs.txt" | httpx-toolkit -ports "$ports" -threads 500 -retries 3 -silent -status-code -json -o "$sd/probe.json" >/dev/null 2>&1 &
        pid=$!; i=0
        while kill -0 "$pid" 2>/dev/null; do
            elapsed=$(($(date +%s) - t_start))
            printf "\r  ${D}┃${N}  ${C}[1/1]${N} ${O}${spin[$i]}${N} ${W}httpx${N}  ${D}${elapsed}s${N}"
            i=$(( (i + 1) % 4 )); sleep 0.2
        done
        wait "$pid"
        elapsed=$(($(date +%s) - t_start))
        jq -r 'select(."status-code" != null) | .input' "$sd/probe.json" 2>/dev/null | sort -u | awk '{print "https://" $0}' > "$sd/alive.txt" || true
        cnt=$(wc -l < "$sd/alive.txt" 2>/dev/null || echo 0)
        for code in 200 201 204 301 302 303 307 308 400 401 403 404 405 410 429 500 502 503; do
          jq -r "select(.\"status-code\" == $code) | .input" "$sd/probe.json" 2>/dev/null | sort -u | awk '{print "https://" $0}' > "$sc_dir/alive${code}.txt" || true
        done
    fi
    printf "\r  ${D}┃${N}  ${C}[1/1]${N} ${G}✓${N} ${W}httpx${N}  ${G}${cnt}${N} ${D}alive${N}  ${D}(${elapsed}s)${N}\n"

    # Run Nuclei scans on alive.txt immediately after extraction
    if [[ "$cnt" -gt 0 ]]; then
        local bd="$sd/raw/bugs"
        mkdir -p "$bd"

        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}springboot-actuator${N}  ${D}checking actuator exposure ...${N}"
        cat "$sd/alive.txt" | nuclei -t $NUCLEI_TEMPLATES/http/technologies/springboot-actuator.yaml -silent -o "$bd/springboot_actuator.txt" &>/dev/null || true

        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}phpinfo-files${N}  ${D}checking phpinfo exposure ...${N}"
        cat "$sd/alive.txt" | nuclei -t $NUCLEI_TEMPLATES/http/exposures/configs/phpinfo-files.yaml -silent -o "$bd/phpinfo_files.txt" &>/dev/null || true

        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}exposed-configs${N}  ${D}scanning configs ...${N}"
        nuclei -l "$sd/alive.txt" -t $NUCLEI_TEMPLATES/http/exposed-configs/ -silent -o "$bd/exposed_configs.txt" &>/dev/null || true

        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}default-logins${N}  ${D}scanning logins ...${N}"
        nuclei -l "$sd/alive.txt" -t $NUCLEI_TEMPLATES/http/default-logins/ -silent -o "$bd/default_logins.txt" &>/dev/null || true

        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}misconfiguration${N}  ${D}scanning misconfigs ...${N}"
        nuclei -l "$sd/alive.txt" -t $NUCLEI_TEMPLATES/http/misconfiguration/ -silent -o "$bd/misconfig.txt" &>/dev/null || true
    fi

    dashboard_update "$sd" 3 "Live Host Probing" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Live hosts found:${N} ${G}${cnt}${N}"
    save_state "$sd" "alive_done"
}

# ── Phase 4 ──
fingerprint_tech() {
    local domain="$1" sd="$2"
    phase_header "4" "Technology Fingerprinting"
    save_state "$sd" "tech"
    dashboard_update "$sd" 4 "Technology Fingerprinting" "running"
    if [[ ! -s "$sd/probe.json" || ! -s "$sd/alive.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No probe data to fingerprint${N}"
        dashboard_update "$sd" 4 "Technology Fingerprinting" "done"
        save_state "$sd" "tech_done"; return
    fi

    local tech_dir="$sd/technologies"
    mkdir -p "$tech_dir"

    echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}tech stack nuclei${N}  ${D}scanning alive hosts ...${N}"
    nuclei -l "$sd/alive.txt" -t "$NUCLEI_TEMPLATES/http/technologies/" -silent -jsonl -o "$tech_dir/tech_nuclei.json" &>/dev/null || true
    local tnc; tnc=$(jq -c '.' "$tech_dir/tech_nuclei.json" 2>/dev/null | wc -l || echo 0)

    echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}waf detect${N}  ${D}checking for WAFs ...${N}"
    nuclei -l "$sd/alive.txt" -t "$NUCLEI_TEMPLATES/http/technologies/waf-detect.yaml" -silent -o "$tech_dir/waf_detect.txt" &>/dev/null || true
    local wc; wc=$(wc -l < "$tech_dir/waf_detect.txt" 2>/dev/null || echo 0)

    # Extract top tech from httpx
    jq -r '.tech[]' "$sd/probe.json" 2>/dev/null | sort | uniq -c | sort -rn > "$tech_dir/tech_stack.txt" || true
    echo -e "  ${D}┃${N}  ${G}✓${N}  ${D}Tech: ${tnc} detect  |  WAF: ${wc} found${N}"

    dashboard_update "$sd" 4 "Technology Fingerprinting" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Tech detections:${N} ${G}${tnc}${N}  ${D}|  WAFs: ${G}${wc}${N}"
    save_state "$sd" "tech_done"
}

# ── Phase 5 ──
scan_ports() {
    local domain="$1" sd="$2"
    phase_header "5" "Port Scanning"
    save_state "$sd" "ports"
    dashboard_update "$sd" 5 "Port Scanning" "running"
    if [[ ! -s "$sd/ips.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No IPs to scan${N}"
        dashboard_update "$sd" 5 "Port Scanning" "done"
        save_state "$sd" "ports_done"; return
    fi

    run_tool "naabu" "$sd/raw/naabu.txt" 1 1 bash -c "naabu -list '$sd/ips.txt' -top-ports 1000 -silent -o '$sd/raw/naabu.txt' >/dev/null 2>&1"
    wait

    dashboard_update "$sd" 5 "Port Scanning" "done"
    local pc; pc=$(wc -l < "$sd/raw/naabu.txt" 2>/dev/null || echo 0)
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Open ports:${N} ${G}${pc}${N}"
    save_state "$sd" "ports_done"
}

# ── Phase 6 ──
enum_endpoints() {
    local domain="$1" sd="$2"
    phase_header "6" "Endpoint Discovery"
    save_state "$sd" "endpoints"
    dashboard_update "$sd" 6 "Endpoint Discovery" "running"
    if [[ ! -s "$sd/alive.txt" ]]; then
        if [[ -s "$sd/subs.txt" ]]; then
            echo -e "  ${D}┃${N}  ${Y}⚠${N}  ${Y}No alive hosts — using subdomains as fallback${N}"
            awk '{print "https://" $0}' "$sd/subs.txt" > "$sd/alive.txt"
        else
            echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No live hosts to crawl${N}"; echo "" > "$sd/allendpoints.txt"
            dashboard_update "$sd" 6 "Endpoint Discovery" "done"
            save_state "$sd" "endpoints_done"; return
        fi
    fi

    local er="$sd/raw/endpoints"; mkdir -p "$er"

    # ── Start kxss watcher for live XSS detection ──
    local kxss_pid=0 kxss_out="$sd/kxss.txt"
    echo -e "  ${D}┃${N}  ${O}⚡${N}  ${W}kxss watcher${N}  ${D}live XSS scanning in background ...${N}"
    (
        touch "$kxss_out"
        while kill -0 "$PPID" 2>/dev/null; do
            local e1="$er/katana.txt" e2="$er/hakrawler.txt" e3="$er/waybackurls.txt" e4="$er/gau.txt"
            cat "$e1" "$e2" "$e3" "$e4" 2>/dev/null | grep -E '\?.' | timeout 10 kxss 2>/dev/null >> "$kxss_out" || cat "$e1" "$e2" "$e3" "$e4" 2>/dev/null | grep -E '\?.' | timeout 10 "$HOME/go/bin/kxss" 2>/dev/null >> "$kxss_out"
            local finds
            finds=$(grep -n '<\|>' "$kxss_out" 2>/dev/null | tail -3)
            if [[ -n "$finds" ]]; then
                while IFS= read -r xline; do
                    local xurl; xurl=$(echo "${xline#*:}" | grep -oE 'https?://[^ ]+' | head -1)
                    echo -e "  ${R}┃${N}  ${R}⚡ XSS:${N} ${W}${xurl:-${xline#*:}}${N}"
                done <<< "$finds"
            fi
            sleep 8
        done
    ) &
    kxss_pid=$!

    # ── Start open redirect watcher ──
    local or_pid=0 or_out="$sd/openredirect.txt" or_seen; or_seen=$(mktemp)
    echo -e "  ${D}┃${N}  ${Y}↗${N}  ${W}open redirect watcher${N}  ${D}checking for redirects in background ...${N}"
    (
        touch "$or_out"
        while kill -0 "$PPID" 2>/dev/null; do
            for or_f in "$er/katana.txt" "$er/hakrawler.txt" "$er/waybackurls.txt" "$er/gau.txt"; do
                [[ ! -f "$or_f" ]] && continue
                grep -ai '=http' "$or_f" 2>/dev/null | head -15 | while IFS= read -r or_url; do
                    [[ -z "$or_url" ]] && continue
                    grep -qF "$or_url" "$or_seen" 2>/dev/null && continue
                    echo "$or_url" >> "$or_seen"
                    local replaced
                    replaced=$(echo "$or_url" | qsreplace 'http://evil.com' 2>/dev/null || echo "$or_url" | "$HOME/go/bin/qsreplace" 'http://evil.com' 2>/dev/null)
                    [[ -z "$replaced" ]] && continue
                    if curl -s -L -m 5 -I "$replaced" 2>/dev/null | grep -q 'http://evil.com'; then
                        echo "$or_url" >> "$or_out"
                        echo -e "  ${R}┃${N}  ${R}↗ REDIRECT:${N} ${W}${or_url}${N}"
                    fi
                done
            done
            sleep 15
        done
    ) &
    or_pid=$!

    run_tool "katana"      "$er/katana.txt"      1 7 bash -c "katana -u '$sd/alive.txt' -silent 2>/dev/null > '$er/katana.txt'"
    run_tool "hakrawler"   "$er/hakrawler.txt"   2 7 bash -c "cat '$sd/alive.txt' | hakrawler -subs 2>/dev/null > '$er/hakrawler.txt'"
    run_tool "waybackurls" "$er/waybackurls.txt" 3 7 bash -c "cat '$sd/alive.txt' | waybackurls 2>/dev/null > '$er/waybackurls.txt'"
    run_tool "gau"         "$er/gau.txt"         4 7 bash -c "cat '$sd/alive.txt' | gau --subs --threads 10 2>/dev/null > '$er/gau.txt'"
    run_tool "gospider"    "$er/gospider.txt"    5 7 bash -c "gospider -S '$sd/alive.txt' -o '$er/gospider_output' 2>/dev/null; find '$er/gospider_output' -type f -exec cat {} + 2>/dev/null | grep -Eo 'https?://[^ \"<>]+' | sort -u > '$er/gospider.txt'; rm -rf '$er/gospider_output'"
    run_tool "paramspider" "$er/paramspider.txt" 6 7 bash -c "paramspider -l '$sd/alive.txt' &>/dev/null; cat results/*.txt 2>/dev/null > '$er/paramspider.txt'; rm -rf results 2>/dev/null"
    run_tool "waybackcdx"  "$er/waybackcdx.txt"  7 7 bash -c "curl -s --max-time 30 -G 'https://web.archive.org/cdx/search/cdx' --data-urlencode 'url=*.$domain/*' --data-urlencode 'collapse=urlkey' --data-urlencode 'output=text' --data-urlencode 'fl=original' > '$er/waybackcdx.txt' 2>/dev/null; [ -s '$er/waybackcdx.txt' ] || true"

    wait

    # ── Stop background watchers ──
    [[ "$kxss_pid" -ne 0 ]] && kill "$kxss_pid" 2>/dev/null && wait "$kxss_pid" 2>/dev/null
    [[ "$or_pid" -ne 0 ]] && kill "$or_pid" 2>/dev/null && wait "$or_pid" 2>/dev/null
    rm -f "$or_seen" 2>/dev/null

    # ── Final kxss pass ──
    echo -e "  ${D}┃${N}  ${O}⚡${N}  ${W}kxss final scan${N}  ${D}checking all endpoints ...${N}"
    cat "$er/katana.txt" "$er/hakrawler.txt" "$er/waybackurls.txt" "$er/gau.txt" 2>/dev/null | grep -E '\?.' | timeout 30 kxss 2>/dev/null >> "$kxss_out" || cat "$er/katana.txt" "$er/hakrawler.txt" "$er/waybackurls.txt" "$er/gau.txt" 2>/dev/null | grep -E '\?.' | timeout 30 "$HOME/go/bin/kxss" 2>/dev/null >> "$kxss_out"
    local kxss_finds
    kxss_finds=$(grep -c '<\|>' "$kxss_out" 2>/dev/null || echo 0)
    if [[ "$kxss_finds" -gt 0 ]]; then
        echo -e "  ${D}┃${N}  ${R}⚡${N}  ${R}XSS POTENTIALS:${N} ${R}${kxss_finds}${N} ${D}found (see kxss.txt)${N}"
        grep -n '<\|>' "$kxss_out" 2>/dev/null | head -5 | while IFS=: read -r _ xcontent; do
            local xurl; xurl=$(echo "$xcontent" | grep -oE 'https?://[^ ]+' | head -1)
            echo -e "  ${D}┃${N}  ${R}  ⚡${N}  ${R}${xurl:-$xcontent}${N}"
        done
    else
        echo -e "  ${D}┃${N}  ${G}✓${N}  ${D}kxss done — no obvious XSS reflections${N}"
    fi

    # ── Final open redirect scan on all endpoints ──
    echo -e "  ${D}┃${N}  ${Y}↗${N}  ${W}open redirect final scan${N}  ${D}checking all endpoints ...${N}"
    grep -hai '=http' "$er/katana.txt" "$er/hakrawler.txt" "$er/waybackurls.txt" "$er/gau.txt" 2>/dev/null | sort -u | while IFS= read -r or_url; do
        local replaced
        replaced=$(echo "$or_url" | qsreplace 'http://evil.com' 2>/dev/null || echo "$or_url" | "$HOME/go/bin/qsreplace" 'http://evil.com' 2>/dev/null)
        [[ -z "$replaced" ]] && continue
        if curl -s -L -m 5 -I "$replaced" 2>/dev/null | grep -q 'http://evil.com'; then
            echo "$or_url" >> "$or_out"
            echo -e "  ${R}┃${N}  ${R}↗ REDIRECT:${N} ${W}${or_url}${N}"
        fi
    done
    if [[ -s "$or_out" ]]; then
        local or_cnt; or_cnt=$(wc -l < "$or_out")
        echo -e "  ${D}┃${N}  ${R}↗${N}  ${R}OPEN REDIRECTS:${N} ${R}${or_cnt}${N} ${D}found (see openredirect.txt)${N}"
    else
        echo -e "  ${D}┃${N}  ${G}✓${N}  ${D}open redirect done — no redirects found${N}"
    fi

    cat "$er"/*.txt 2>/dev/null | sort -u > "$sd/allendpoints.txt"
    local cnt; cnt=$(wc -l < "$sd/allendpoints.txt" 2>/dev/null || echo 0)
    dashboard_update "$sd" 6 "Endpoint Discovery" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Endpoints collected:${N} ${G}${cnt}${N} ${D}unique${N}"
    save_state "$sd" "endpoints_done"
}

# ── Phase 7 ──
extract_params() {
    local domain="$1" sd="$2"
    phase_header "7" "Parameter Extraction (gf)"
    save_state "$sd" "params"
    dashboard_update "$sd" 7 "Parameter Extraction" "running"
    if [[ ! -s "$sd/allendpoints.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No endpoints to extract params from${N}"
        dashboard_update "$sd" 7 "Parameter Extraction" "done"
        save_state "$sd" "params_done"; return
    fi

    local pd="$sd/raw/params"; mkdir -p "$pd"

    for pattern in xss ssrf lfi rce sqli ssti redirect idor; do
        gf "$pattern" "$sd/allendpoints.txt" 2>/dev/null | sort -u > "$pd/${pattern}.txt" || true
        local count; count=$(wc -l < "$pd/${pattern}.txt" 2>/dev/null || echo 0)
        printf "  ${D}┃${N}  ${C}▸${N}  gf %-10s  ${D}→${N}  ${W}%s${N} URLs\n" "$pattern" "$count"
    done

    local total; total=$(cat "$pd"/*.txt 2>/dev/null | sort -u | wc -l || echo 0)
    dashboard_update "$sd" 7 "Parameter Extraction" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Parameterized URLs:${N} ${G}${total}${N}"
    save_state "$sd" "params_done"
}

# ── Phase 8 ──
extract_js() {
    local domain="$1" sd="$2"
    phase_header "8" "JavaScript Collection & Analysis"
    save_state "$sd" "js_extract"
    dashboard_update "$sd" 8 "JavaScript Collection & Analysis" "running"
    if [[ ! -s "$sd/allendpoints.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No endpoints to process${N}"; echo "" > "$sd/jsfile.txt"
        dashboard_update "$sd" 8 "JavaScript Collection & Analysis" "done"
        save_state "$sd" "js_extract_done"; return
    fi

    echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}Filtering JS files from endpoints${N}"
    grep -iE '\.js($|\?)' "$sd/allendpoints.txt" > "$sd/jsfile.txt" 2>/dev/null || true
    grep -ivE '\.js($|\?)' "$sd/allendpoints.txt" > "$sd/allendpoints.tmp" 2>/dev/null && mv "$sd/allendpoints.tmp" "$sd/allendpoints.txt"

    local jcnt; jcnt=$(wc -l < "$sd/jsfile.txt" 2>/dev/null || echo 0)
    echo -e "  ${D}┃${N}  ${G}✓${N}  ${D}JS files: ${jcnt}${N}"

    if [[ ! -s "$sd/jsfile.txt" ]]; then
        echo -e "  ${D}┃${N}  ${Y}╳${N}  ${Y}No JS files to analyze${N}"
        dashboard_update "$sd" 8 "JavaScript Collection & Analysis" "done"
        save_state "$sd" "js_extract_done"; return
    fi

    local jd="$sd/js_hunt"; mkdir -p "$jd" "$jd/files"
    local total=5

    run_tool "download-js" "$jd/downloaded.txt" 1 $total bash -c "while IFS= read -r url; do f=\$(echo \"\$url\" | md5sum | cut -d' ' -f1); curl -sL --max-time 15 -o '$jd/files/\$f.js' \"\$url\" 2>/dev/null && echo \"\$url\" >> '$jd/downloaded.txt'; done < '$sd/jsfile.txt'"

    run_tool "mantra"      "$jd/mantra.txt"     2 $total bash -c "cat '$sd/jsfile.txt' | mantra -s -d 2>/dev/null > '$jd/mantra.txt'"

    run_tool "deep-scan"   "$jd/deepscan.txt"   3 $total bash -c "cd '$jd/files' && { \
      grep -rhaE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' . 2>/dev/null; \
      grep -rhaE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' . 2>/dev/null; \
      grep -rhaE '(sk|pk)_(live|test)_[A-Za-z0-9]{10,}' . 2>/dev/null; \
      grep -rhaE 'gh[pousr]_[A-Za-z0-9]{36,}' . 2>/dev/null; \
      grep -rhaE 'SG\.[A-Za-z0-9_-]{20,}' . 2>/dev/null; \
      grep -rhaE 'AIza[0-9A-Za-z_-]{35}' . 2>/dev/null; \
      grep -rhaE '-----BEGIN (RSA |EC )?PRIVATE KEY-----' . 2>/dev/null; \
      grep -rhaE 'mongodb(\+srv)?://[^\"<> ]+' . 2>/dev/null; \
      grep -rhaE 'glpat-[A-Za-z0-9_-]{20,}' . 2>/dev/null; \
      grep -rhaE 'key-[0-9a-f]{32}' . 2>/dev/null; \
      grep -rhaE 'pk\.eyJ[A-Za-z0-9_-]{30,}' . 2>/dev/null; \
      grep -rhaE 'hooks\.slack\.com/services/[A-Za-z0-9/]+' . 2>/dev/null; \
      grep -rhaE 'redis://[^\"<> ]+' . 2>/dev/null; \
      grep -rhaE 'postgresql://[^\"<> ]+' . 2>/dev/null; \
    } > '$jd/deepscan.txt'"

    run_tool "endpoints"   "$jd/endpoints.txt"  4 $total bash -c "grep -roaE '/[a-zA-Z0-9_/.-]*(api|v[0-9]|graphql|rest|auth|oauth|token|admin|dashboard|console|swagger|health|actuator)[a-zA-Z0-9_/.-]*' '$jd/files/' 2>/dev/null | sort -u > '$jd/endpoints.txt'"

    run_tool "gitleaks"    "$jd/gitleaks.txt"   5 $total bash -c "gitleaks detect --source '$jd/files' --no-git --silent 2>/dev/null | grep -oE 'Description: .*' | sort -u > '$jd/gitleaks.txt'"

    wait

    local dloaded mantra_cnt deep_cnt ep_cnt gl_cnt
    dloaded=$(wc -l < "$jd/downloaded.txt" 2>/dev/null || echo 0)
    mantra_cnt=$(wc -l < "$jd/mantra.txt" 2>/dev/null || echo 0)
    deep_cnt=$(wc -l < "$jd/deepscan.txt" 2>/dev/null || echo 0)
    ep_cnt=$(wc -l < "$jd/endpoints.txt" 2>/dev/null || echo 0)
    gl_cnt=$(wc -l < "$jd/gitleaks.txt" 2>/dev/null || echo 0)
    rm -rf "$jd/files" 2>/dev/null

    dashboard_update "$sd" 8 "JavaScript Collection & Analysis" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}JS downloaded:${N} ${G}${dloaded}${N}  ${D}|  Mantra: ${G}${mantra_cnt}${N}  ${D}|  Secrets: ${G}${deep_cnt}${N}  ${D}|  Endpoints: ${G}${ep_cnt}${N}  ${D}|  Gitleaks: ${G}${gl_cnt}${N}"
    save_state "$sd" "js_extract_done"
}

# ── Phase 9: Bug Detection ──
detect_bugs() {
    local domain="$1" sd="$2"
    phase_header "9" "Bug Detection & Quick Wins"
    save_state "$sd" "bugs"
    dashboard_update "$sd" 9 "Bug Detection & Quick Wins" "running"
    local bd="$sd/raw/bugs"; mkdir -p "$bd"

    if [[ -s "$sd/alive.txt" ]]; then
        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}quick-win nuclei${N}  ${D}scanning for panels ...${N}"
        nuclei -l "$sd/alive.txt" -t "$NUCLEI_TEMPLATES/http/panels/" -silent -o "$bd/panels.txt" &>/dev/null || true
    fi

    if [[ -s "$sd/allendpoints.txt" ]]; then
        echo -e "  ${D}┃${N}  ${O}▶${N}  ${W}endpoint nuclei${N}  ${D}scanning endpoints ...${N}"
        nuclei -l "$sd/allendpoints.txt" -t "$NUCLEI_TEMPLATES/http/vulnerabilities/" -silent -o "$bd/vulns.txt" &>/dev/null || true
    fi

    local ec; ec=$(wc -l "$bd/exposed_configs.txt" 2>/dev/null | awk '{print $1}')
    local dl; dl=$(wc -l "$bd/default_logins.txt" 2>/dev/null | awk '{print $1}')
    local pc; pc=$(wc -l "$bd/panels.txt" 2>/dev/null | awk '{print $1}')
    local mc; mc=$(wc -l "$bd/misconfig.txt" 2>/dev/null | awk '{print $1}')
    local vc; vc=$(wc -l "$bd/vulns.txt" 2>/dev/null | awk '{print $1}')
    local sa; sa=$(wc -l "$bd/springboot_actuator.txt" 2>/dev/null | awk '{print $1}')
    local pf; pf=$(wc -l "$bd/phpinfo_files.txt" 2>/dev/null | awk '{print $1}')
    local total_bugs=$((ec + dl + pc + mc + vc + sa + pf))

    echo -e "  ${D}┃${N}  ${G}✓${N}  ${D}Configs: ${ec}  Logins: ${dl}  Panels: ${pc}  Misconfigs: ${mc}  Vulns: ${vc}  SpringActuator: ${sa}  PhpInfo: ${pf}${N}"
    dashboard_update "$sd" 9 "Bug Detection & Quick Wins" "done"
    phase_sep
    echo -e "  ${G}◆${N}  ${W}Bug findings:${N} ${G}${total_bugs}${N}"
    save_state "$sd" "bugs_done"
}

# ── Summary ──
summary() {
    local d="$1" sd="$2" st="$3"
    local et=$(( $(date +%s) - st ))
    local s=0 a=0 e=0 j=0 i=0 c=0 js=0 t=0 p=0 pr=0 b=0
    [[ -f "$sd/subs.txt" ]]         && s=$(wc -l < "$sd/subs.txt")
    [[ -f "$sd/alive.txt" ]]        && a=$(wc -l < "$sd/alive.txt")
    [[ -f "$sd/allendpoints.txt" ]] && e=$(wc -l < "$sd/allendpoints.txt")
    [[ -f "$sd/jsfile.txt" ]]       && j=$(wc -l < "$sd/jsfile.txt")
    [[ -f "$sd/ips.txt" ]]          && i=$(wc -l < "$sd/ips.txt")
    [[ -f "$sd/cidrs.txt" ]]        && c=$(wc -l < "$sd/cidrs.txt")
    [[ -f "$sd/technologies/tech_nuclei.json" ]] && t=$(jq -c '.' "$sd/technologies/tech_nuclei.json" 2>/dev/null | wc -l)
    [[ -f "$sd/raw/naabu.txt" ]]    && p=$(wc -l < "$sd/raw/naabu.txt")
    [[ -d "$sd/raw/params" ]]       && pr=$(cat "$sd/raw/params"/*.txt 2>/dev/null | sort -u | wc -l)
    [[ -f "$sd/js_hunt/secrets.txt" || -f "$sd/js_hunt/deepscan.txt" ]] && js=$(cat "$sd/js_hunt/secrets.txt" "$sd/js_hunt/deepscan.txt" 2>/dev/null | wc -l)
    [[ -d "$sd/raw/bugs" ]]         && b=$(cat "$sd/raw/bugs"/*.txt 2>/dev/null | wc -l)
    local mins=$((et / 60)) secs=$((et % 60))

    echo ""
    echo -e "  ${G}✔${N} ${W}HUNT PIPELINE RUN COMPLETE${N}"
    echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${W}%s${N}\n" "Target" "$d"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Subdomains" "$s"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Alive hosts" "$a"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s / %s${N}\n" "IPs / CIDRs" "$i" "$c"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Tech detections" "$t"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Open ports" "$p"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Endpoints" "$e"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Param URLs" "$pr"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "JS files" "$j"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "JS secrets" "$js"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${G}%s${N}\n" "Bug findings" "$b"
    printf "  ${D}│${N}  %-22s ${D}▸${N}  ${W}%dm %ds${N}\n" "Time taken" "$mins" "$secs"
    echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "  ${D}Output Directory ${D}▸${N} ${C}${sd}${N}"
    echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""
}

# ── Pipeline ──
process_domain() {
    local domain="$1" orig_dir; orig_dir=$(pwd)
    domain=$(echo "$domain" | /usr/bin/tr '[:upper:]' '[:lower:]' | sed 's|^https\?://||;s|/.*$||;s|^www\.||' | /usr/bin/tr -d '[:space:]')
    [[ -z "$domain" ]] && return
    local sd="$(pwd)/nucleiresults/$domain" st; st=$(date +%s)
    mkdir -p "$sd"
    pushd "$sd" >/dev/null || return
    dashboard_init "$domain" "$sd"
    dashboard_open "$sd"

    local phase; phase=$(read_phase "$sd")

    # ── Show resume status panel ──
    if [[ "$phase" != "start" ]]; then
        local pname="$phase"
        local icon="${O}▶${N}"
        pname="${phase/_done/}"
        case "$pname" in
            subdomains) pname="Subdomain Enumeration" ;;
            ips)        pname="IP Extraction & Resolution" ;;
            alive)      pname="Live Host Probing" ;;
            tech)       pname="Tech Fingerprinting" ;;
            ports)      pname="Port Scanning" ;;
            endpoints)  pname="Endpoint Discovery" ;;
            params)     pname="Parameter Extraction" ;;
            js_extract) pname="JS Collection & Analysis" ;;
            bugs)       pname="Bug Detection" ;;
            done)       pname="Complete"; icon="${G}✓${N}" ;;
        esac
        echo -e "  ${O}🔄${N} ${W}SESSION RESUME${N} ${D}│${N} ${W}$domain${N}"
        echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
        echo -e "  ${icon}  ${D}Current Phase ${D}▸${N} ${W}$pname${N}"
        [[ -f "$sd/subs.txt" ]]         && printf "  ${D}│${N}  %-18s ${D}▸${N}  ${G}%s${N} collected\n" "Subdomains" "$(wc -l < "$sd/subs.txt")"
        [[ -f "$sd/alive.txt" ]]        && printf "  ${D}│${N}  %-18s ${D}▸${N}  ${G}%s${N} found\n" "Alive Hosts" "$(wc -l < "$sd/alive.txt")"
        [[ -f "$sd/ips.txt" ]]          && printf "  ${D}│${N}  %-18s ${D}▸${N}  ${G}%s${N} resolved\n" "IPs" "$(wc -l < "$sd/ips.txt")"
        [[ -f "$sd/allendpoints.txt" ]] && printf "  ${D}│${N}  %-18s ${D}▸${N}  ${G}%s${N} discovered\n" "Endpoints" "$(wc -l < "$sd/allendpoints.txt")"
        echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
        echo ""

    fi

    if [[ "$phase" == "done" && ${FORCE:-0} -eq 0 ]]; then
        summary "$domain" "$sd" "$st"; popd >/dev/null; return
    fi
    if [[ "$FORCE" -eq 1 ]]; then
        echo -e "  ${Y}◆${N}  ${Y}Force re-run:${N} ${W}$domain${N}"
        rm -rf "$sd" && mkdir -p "$sd" && phase="start"
    fi

    [[ "$phase" == "start" || "$phase" == "subdomains" ]]           && enum_subs "$domain" "$sd/raw/subs" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] subdomains done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "subdomains_done" || "$phase" == "ips" ]]        && extract_ips "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] ips done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "ips_done" || "$phase" == "alive" ]]             && probe_alive "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] alive done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "alive_done" || "$phase" == "tech" ]]             && fingerprint_tech "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] tech done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "tech_done" || "$phase" == "ports" ]]             && scan_ports "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] ports done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "ports_done" || "$phase" == "endpoints" ]]       && enum_endpoints "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] endpoints done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "endpoints_done" || "$phase" == "params" ]]      && extract_params "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] params done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "params_done" || "$phase" == "js_extract" ]]     && extract_js "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] js extract done${N}"

    phase=$(read_phase "$sd")
    [[ "$phase" == "js_extract_done" || "$phase" == "bugs" ]]          && detect_bugs "$domain" "$sd" \
        || echo -e "  ${D}┃${N}  ${C}◆${N}  ${D}[resume] bug detection done${N}"

    save_state "$sd" "done"
    summary "$domain" "$sd" "$st"
    popd >/dev/null
}

# ── Session Management ──
list_sessions() {
    echo ""
    echo -e "  ${O}📋${N} ${W}DARK-KNIGHT ACTIVE SESSIONS${N}"
    echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    local found=0
    for d in nucleiresults/*/; do
        [ -d "$d" ] || continue
        local sf="${d}.hunt_state"
        if [[ -f "$sf" ]]; then
            local ph; ph=$(grep -oP 'PHASE=\K.*' "$sf" 2>/dev/null || echo "unknown")
            local ts; ts=$(grep -oP 'TS=\K.*' "$sf" 2>/dev/null || echo "0")
            local age=$(( $(date +%s) - ts ))
            local dirname="${d%/}"
            ph=$(echo "$ph" | sed 's/_done//')
            local icon="○"
            [[ "$ph" == "done" ]] && icon="${G}✓${N}" || icon="${O}▶${N}"
            [[ "$ph" == "done" ]] && ph="${G}complete${N}" || ph="${C}${ph}${N}"
            printf "  ${D}│${N}  %b  %-22s ${D}▸${N}  %-12b ${D}(%dm ago)${N}\n" "$icon" "$dirname" "$ph" $((age / 60))
            found=1
        fi
    done
    [[ "$found" -eq 0 ]] && echo -e "  ${D}│  No active sessions found${N}"
    echo -e "  ${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""
    echo -e "  ${D}Usage:${N} ${W}hunt -r <name>${N}  ${D}to resume a session${N}"
    echo -e "  ${D}       ${W}hunt --fresh <domain>${N}  ${D}to start fresh${N}"
    echo ""
}

show_banner() {
    # Custom neon colors for banner
    local C1='\033[38;5;201m' # Pink/Purple
    local C2='\033[38;5;135m' # Purple-blue
    local C3='\033[38;5;33m'  # Bright Blue
    local C4='\033[38;5;51m'  # Neon Cyan
    local WH='\033[1;37m'
    local DG='\033[90m'
    local RST='\033[0m'
    
    echo -e ""
    echo -e "  ${C1} ___   _   ___ _  _   _  _ _  ___ _  _ _____ ${RST}"
    echo -e "  ${C2} |   \\ /_\\ | _ \\ |/ /  | |/ / \\| |_| |_|_   _|${RST}"
    echo -e "  ${C3} | |) / _ \\|   / ' <   | ' <| .\` | | ' \\ | |  ${RST}"
    echo -e "  ${C4} |___/_/ \\_\\_|_\\_|\\_\\  |_|\\_\\_|\\_|_|_||_||_|  ${RST}"
    echo -e "  ${DG}  ───────────────────────────────────────────────${RST}"
    echo -e "  ${DG}  ⚡ ${WH}CYBERSECURITY RECON & DETECTION PIPELINE${RST} ${DG}│${RST} ${C4}v${VERSION}${RST}"
    echo -e "  ${DG}  ───────────────────────────────────────────────${RST}"
    echo -e ""
}

show_usage() {
    echo -e "  ${R}❌ Usage: hunt <domain|file> [options]${N}"
    echo -e ""
    echo -e "  ${D}Examples:${N}"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt target.com" "Full recon pipeline"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt domains.txt" "Batch mode from file"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt -s subs.txt" "Skip enum, use subdomain list"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt -r target.com" "Resume existing session"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt -l" "List active sessions"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt --fresh target.com" "Start fresh (delete old)"
    printf "    ${W}%-24s${N} ${D}%-30s${N}\n" "hunt target.com --force" "Force re-run"
    echo -e ""
    exit 1
}


extract_domain() {
    local file="$1"
    awk -F. '{if(NF>=2) print tolower($(NF-1)"."$NF)}' "$file" | grep -v '^\s*$' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}

# ── Main ──
main() {
    local all_start; all_start=$(date +%s)
    show_banner
    check_deps

    MODE="hunt"   # hunt, resume, list, fresh, subs
    TARGET=""
    SUBS_FILE=""

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--list)       MODE="list"; shift ;;
            -r|--resume)     MODE="resume"; shift; [[ $# -gt 0 ]] && { TARGET="$1"; shift; } ;;
            --fresh)         MODE="fresh"; shift; [[ $# -gt 0 ]] && { TARGET="$1"; shift; } ;;
            -s|--subs)       MODE="subs"; shift; [[ $# -gt 0 ]] && { SUBS_FILE="$1"; shift; } ;;
            --force)         FORCE=1; shift ;;
            -*)              echo -e "  ${R}┃${N}  ${R}✗${N}  Unknown option: $1"; show_usage ;;
            *)               [[ -z "$TARGET" ]] && TARGET="$1"; shift ;;
        esac
    done

    [[ -z "$TARGET" && "$MODE" != "list" && "$MODE" != "subs" ]] && show_usage

    # ── List sessions ──
    if [[ "$MODE" == "list" ]]; then
        list_sessions; return
    fi

    # ── Resume mode ──
    if [[ "$MODE" == "resume" ]]; then
        local sdir="$(pwd)/nucleiresults/$TARGET"
        if [[ -d "$sdir" && -f "$sdir/.hunt_state" ]]; then
            local ph; ph=$(grep -oP 'PHASE=\K.*' "$sdir/.hunt_state" 2>/dev/null || echo "unknown")
            if [[ "$ph" == "done" && "$FORCE" -eq 0 ]]; then
                echo -e "  ${C}◆${N}  ${D}Session${N} ${W}$TARGET${N} ${D}is already complete. Use${N} ${W}--force${N} ${D}to re-run.${N}"
                local st; st=$(grep -oP 'TS=\K.*' "$sdir/.hunt_state" 2>/dev/null || echo "$(date +%s)")
                summary "$TARGET" "$sdir" "$st"; return
            fi
            echo -e "  ${C}◆${N}  ${W}Resuming session:${N} ${C}$TARGET${N}  ${D}(phase: ${ph})${N}"
            process_domain "$TARGET"; return
        else
            echo -e "  ${R}┃${N}  ${R}✗${N}  No session found: ${W}$TARGET${N}"
            echo -e "  ${R}┃${N}  ${D}Use${N} ${W}hunt -l${N} ${D}to list available sessions${N}"
            exit 1
        fi
    fi

    # ── Fresh mode ──
    if [[ "$MODE" == "fresh" ]]; then
        FORCE=1
        local ndir="$(pwd)/nucleiresults/$TARGET"
        if [[ -d "$ndir" ]]; then
            echo -e "  ${Y}◆${N}  ${Y}Fresh start:${N} ${W}$TARGET${N}  ${D}(deleting old session)${N}"
            rm -rf "$ndir"
        fi
        process_domain "$TARGET"; return
    fi

    # ── Subdomain list mode ──
    if [[ "$MODE" == "subs" ]]; then
        if [[ ! -f "$SUBS_FILE" ]]; then
            echo -e "  ${R}┃${N}  ${R}✗${N}  Subdomain file not found: ${W}$SUBS_FILE${N}"; exit 1
        fi
        local base_domain="${TARGET:-$(extract_domain "$SUBS_FILE")}"
        if [[ -z "$base_domain" ]]; then
            echo -e "  ${R}┃${N}  ${R}✗${N}  Could not extract domain. Specify target: ${W}hunt -s subs.txt target.com${N}"
            exit 1
        fi
        echo -e "  ${C}◆${N}  ${W}Subdomain list mode${N}  ${D}─${N}  ${C}$SUBS_FILE${N}  ${D}→${N}  ${W}$base_domain${N}"
        local subcnt; subcnt=$(wc -l < "$SUBS_FILE")
        echo -e "  ${C}◆${N}  ${D}Skipping Phase 1 (using ${subcnt} subs from file)${N}"

        local sd="$(pwd)/nucleiresults/$base_domain"
        mkdir -p "$sd"
        sort -u "$SUBS_FILE" > "$sd/subs.txt"
        mkdir -p "$sd/raw/subs"
        cp "$sd/subs.txt" "$sd/raw/subs/from_file.txt"
        save_state "$sd" "subdomains_done"
        process_domain "$base_domain"; return
    fi

    # ── Normal hunt mode ──
    if [[ -f "$TARGET" ]]; then
        echo -e "  ${C}◆${N}  ${W}File mode${N}  ${D}─${N}  ${D}$TARGET${N}"
        while IFS= read -r line; do
            line=$(echo "$line" | /usr/bin/tr -d '[:space:]')
            [[ -n "$line" && ! "$line" =~ ^# ]] || continue
            echo -e "\n  ${O}━━━${N}  ${W}$line${N}  ${O}━━━${N}"
            process_domain "$line"
        done < "$TARGET"
    else
        # Auto-resume: if session dir exists, show resume header
        local adir="$(pwd)/nucleiresults/$TARGET"
        if [[ -d "$adir" && -f "$adir/.hunt_state" && "$FORCE" -eq 0 ]]; then
            local aph; aph=$(grep -oP 'PHASE=\K.*' "$adir/.hunt_state" 2>/dev/null || echo "unknown")
            echo -e "  ${C}◆${N}  ${W}Auto-resume:${N} ${C}$TARGET${N}  ${D}(phase: ${aph})${N}"
            echo -e "  ${C}◆${N}  ${D}Use${N} ${W}--fresh${N} ${D}to restart or${N} ${W}-r${N} ${D}for explicit resume${N}"
        fi
        process_domain "$TARGET"
    fi

    local total=$(( $(date +%s) - all_start ))
    local mins=$((total / 60)) secs=$((total % 60))
    echo ""
    echo -e "  ${G}◆${N}  ${W}Total time:${N}  ${G}${mins}m ${secs}s${N}"
    echo -e "  ${G}◆${N}  ${W}All tasks completed.${N}"
    echo ""
}

FORCE=0
main "$@"
