#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

scan_th() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [TruffleHog Matrix Worker] Extracting JS URLs from gau and waybackurls..."
    (echo "$domain" | gau 2>/dev/null; echo "$domain" | waybackurls 2>/dev/null) | grep -E '\.js($|\?)' 2>/dev/null | sort -u | head -n 50 > "results/${domain}_js_urls_temp.txt"

    if [ -s "results/${domain}_js_urls_temp.txt" ]; then
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"
        
        echo "[+] [$domain] Downloading JS targets with random delay (Anti-WAF)..."
        wget -P "$download_dir" \
             -i "results/${domain}_js_urls_temp.txt" \
             --copies=1 --tries=1 \
             --timeout=5 \
             --wait=1 \
             --random-wait \
             --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 2>/dev/null || true
        
        echo "[+] [$domain] Running TruffleHog verified filesystem scan..."
        trufflehog filesystem "$download_dir" --only-verified --plain 2>/dev/null > "results/${domain}_trufflehog.txt"
        
        rm -rf "$download_dir"
    else
        echo "  -> [$domain] No JS assets found for TruffleHog."
    fi
    rm -f "results/${domain}_js_urls_temp.txt"
}

export -f scan_th
echo "[*] Starting Dynamic Matrix TruffleHog Scanner for $TARGET_FILE..."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'scan_th "{}"'

rm -f targets_group*
