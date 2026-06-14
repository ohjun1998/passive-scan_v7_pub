#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

# 💡 가상머신 20대 분산 폭격을 위한 타겟 리스트 20분할
split -d -n l/20 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [Stage 1: Collector] Fetching passive URLs from APIs..."
    
    # 💡 [서브도메인 차단 필터] 타겟 도메인과 정확히 일치하는(시작하는) 주소만 추출합니다.
    echo "$domain" | gau | grep -iE "^https?://${domain}(/|$)" > "results/${domain}_gau.txt" 2>/dev/null
    sort -u "results/${domain}_gau.txt" -o "results/${domain}_gau.txt"

    echo "$domain" | waybackurls | grep -iE "^https?://${domain}(/|$)" > "results/${domain}_waybackurls.txt" 2>/dev/null
    sort -u "results/${domain}_waybackurls.txt" -o "results/${domain}_waybackurls.txt"

    cat "results/${domain}_gau.txt" "results/${domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\?)' 2>/dev/null | sort -u > "results/${domain}_js_master_list.txt"
    
    local total_js=$(wc -l < "results/${domain}_js_master_list.txt")
    echo "  -> [$domain] Successfully indexed $total_js unique strict JS targets."

    if [ "$total_js" -gt 0 ]; then
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"
        
        rm -f "results/${domain}_js_mapping.txt"

        head -n 4000 "results/${domain}_js_master_list.txt" | while read -r url; do
            if [[ "$url" =~ ^https?:// ]]; then echo "$url"
            elif [[ "$url" =~ ^// ]]; then echo "https:$url"
            elif [[ "$url" =~ ^/ ]]; then echo "https://$domain$url"
            else echo "https://$domain/$url"
            fi
        done > "results/${domain}_js_urls_clean.txt"

        while read -r url; do
            [[ -z "$url" ]] && continue
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            echo -e "${safe_name}\t${url}" >> "results/${domain}_js_mapping.txt"
        done < "results/${domain}_js_urls_clean.txt"

        shuf "results/${domain}_js_urls_clean.txt" -o "results/${domain}_js_urls_shuffled.txt"
        
        local success_cnt=0
        local fail_cnt=0
        local current=0
        local total_download=$(wc -l < "results/${domain}_js_urls_shuffled.txt")

        while read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            
            if curl -s -L --connect-timeout 1 --max-time 4 --fail \
                 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                 "$url" -o "$download_dir/$safe_name"; then
                echo "    [✓] [${domain}] (${current}/${total_download}) Download Success"
                ((success_cnt++))
            else
                echo "    [✗] [${domain}] (${current}/${total_download}) Download Failed"
                ((fail_cnt++))
            fi
            sleep 0.5
        done < "results/${domain}_js_urls_shuffled.txt"

        rm -f "results/${domain}_js_urls_clean.txt" "results/${domain}_js_urls_shuffled.txt"
    fi
}

export -f collect_master
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'
rm -f targets_group*
