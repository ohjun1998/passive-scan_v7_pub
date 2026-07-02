#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/20 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local raw_domain=$(echo "$1" | xargs)
    [[ -z "$raw_domain" || "$raw_domain" =~ ^# ]] && return

    local base_domain="$raw_domain"
    local safe_domain="$raw_domain"
    local regex="^https?://${raw_domain//./\.}(/|$)"

    if [[ "$raw_domain" == \** ]]; then
        base_domain="${raw_domain#\*.}"
        safe_domain="wild_${base_domain}"
        regex="^https?://([a-zA-Z0-9.-]+\.)?${base_domain//./\.}(/|$)"
        echo "[+] [${raw_domain}] 🔍 와일드카드 감지: Subfinder 전수조사..."
        
        subfinder -d "$base_domain" -all -silent > "results/${safe_domain}_subs.txt"
        echo "$base_domain" >> "results/${safe_domain}_subs.txt"
        sort -u "results/${safe_domain}_subs.txt" -o "results/${safe_domain}_subs.txt"
        
        shuf -n 1000 "results/${safe_domain}_subs.txt" -o "results/${safe_domain}_subs.txt" 2>/dev/null || true
        
        cat "results/${safe_domain}_subs.txt" | timeout 5m gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        cat "results/${safe_domain}_subs.txt" | timeout 5m waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    else
        echo "[+] [${raw_domain}] 🔍 단일 도메인 정찰..."
        echo "$base_domain" | timeout 5m gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        echo "$base_domain" | timeout 5m waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    fi

    grep -iE "$regex" "results/${safe_domain}_gau.txt" | sort -u -o "results/${safe_domain}_gau.txt"
    grep -iE "$regex" "results/${safe_domain}_waybackurls.txt" | sort -u -o "results/${safe_domain}_waybackurls.txt"

    echo "[+] [${raw_domain}] 🕷️ Katana 지능형 크롤링 준비..."
    cat "results/${safe_domain}_gau.txt" "results/${safe_domain}_waybackurls.txt" 2>/dev/null | sort -u > "results/${safe_domain}_raw_seed.txt"
    
    shuf -n 50000 "results/${safe_domain}_raw_seed.txt" -o "results/${safe_domain}_raw_seed.txt" 2>/dev/null || true
    uro -i "results/${safe_domain}_raw_seed.txt" -o "results/${safe_domain}_clean_seed.txt"

    shuf -n 300 "results/${safe_domain}_clean_seed.txt" > "results/${safe_domain}_katana_seed.txt" 2>/dev/null || cp "results/${safe_domain}_clean_seed.txt" "results/${safe_domain}_katana_seed.txt"

    echo "  -> [Katana] Depth 3 크롤링 시작 (최대 15분 타임아웃)..."
    timeout 15m katana -list "results/${safe_domain}_katana_seed.txt" -d 3 -jc -kf all -c 2 -rl 50 -ct 10 -silent > "results/${safe_domain}_katana.txt" 2>/dev/null
    grep -iE "$regex" "results/${safe_domain}_katana.txt" | sort -u -o "results/${safe_domain}_katana.txt"
    
    rm -f "results/${safe_domain}_raw_seed.txt" "results/${safe_domain}_clean_seed.txt" "results/${safe_domain}_katana_seed.txt"

    # 💡 [핵심 패치 1] 무의미한 오픈소스 JS 라이브러리를 강력한 정규식으로 차단하여 고가치 JS 파일만 추출
    cat "results/${safe_domain}_gau.txt" "results/${safe_domain}_waybackurls.txt" "results/${safe_domain}_katana.txt" 2>/dev/null \
        | grep -E '\.js($|\?)' 2>/dev/null \
        | grep -vE -i '(jquery|bootstrap|vue|react|angular|moment|lodash|underscore|vendor|node_modules|polyfill|webpack)' \
        | sort -u > "results/${safe_domain}_js_raw_list.txt"
    
    > "results/${safe_domain}_js_master_list.txt"
    while read -r url; do
        [[ -z "$url" ]] && continue
        if [[ "$url" =~ ^https?:// ]]; then echo "$url"
        elif [[ "$url" =~ ^// ]]; then echo "https:$url"
        elif [[ "$url" =~ ^/ ]]; then echo "https://$base_domain$url"
        else echo "https://$base_domain/$url"
        fi
    done < "results/${safe_domain}_js_raw_list.txt" | sort -u > "results/${safe_domain}_js_master_list.txt"

    local total_js=$(wc -l < "results/${safe_domain}_js_master_list.txt")
    echo "  -> [성공] 필터링 된 ${total_js}개의 고가치 자바스크립트(JS) 소스 경로 식별"

    if [ "$total_js" -gt 0 ]; then
        if [ -f "global_js_db.txt" ]; then
            sort -u global_js_db.txt -o global_js_db_sorted.txt
            comm -23 "results/${safe_domain}_js_master_list.txt" global_js_db_sorted.txt > "results/${safe_domain}_js_new_list.txt"
        else
            cp "results/${safe_domain}_js_master_list.txt" "results/${safe_domain}_js_new_list.txt"
        fi

        local total_new_js=$(wc -l < "results/${safe_domain}_js_new_list.txt")
        echo "  -> [신규 JS 필터링] ${total_new_js}개의 새로운 JS 파일을 발견했습니다."

        if [ "$total_new_js" -gt 0 ]; then
            local download_dir="results/${safe_domain}_js_files"
            mkdir -p "$download_dir"
            rm -f "results/${safe_domain}_js_mapping.txt"

            shuf "results/${safe_domain}_js_new_list.txt" > "results/${safe_domain}_js_urls_target.txt"
            
            local MAX_SUCCESS=500
            local success_cnt=0
            local fail_cnt=0

            while read -r url; do
                [[ -z "$url" ]] && continue
                local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
                
                if curl -s -L --connect-timeout 2 --max-time 3 --fail \
                     -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36" \
                     "$url" -o "$download_dir/$safe_name"; then
                    
                    ((success_cnt++))
                    echo -e "${safe_name}\t${url}" >> "results/${safe_domain}_js_mapping.txt"
                    if [ "$success_cnt" -ge "$MAX_SUCCESS" ]; then break; fi
                else
                    ((fail_cnt++))
                fi
            done < "results/${safe_domain}_js_urls_target.txt"
            echo "  -> 다운로드 완료: ${success_cnt}개 확보"
        fi
    fi
}

export -f collect_master
xargs -P 2 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
