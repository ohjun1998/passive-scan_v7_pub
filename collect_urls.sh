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
        
        # 💡 서브도메인 샘플링 한도 2배 상향 (1000 -> 2000)
        shuf -n 2000 "results/${safe_domain}_subs.txt" -o "results/${safe_domain}_subs.txt" 2>/dev/null || true
        
        # 💡 아카이브 수집 타임아웃 연장 (5m -> 10m)
        cat "results/${safe_domain}_subs.txt" | timeout 10m gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        cat "results/${safe_domain}_subs.txt" | timeout 10m waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    else
        echo "[+] [${raw_domain}] 🔍 단일 도메인 정찰..."
        # 💡 아카이브 수집 타임아웃 연장 (5m -> 10m)
        echo "$base_domain" | timeout 10m gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        echo "$base_domain" | timeout 10m waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    fi

    grep -iE "$regex" "results/${safe_domain}_gau.txt" | sort -u -o "results/${safe_domain}_gau.txt"
    grep -iE "$regex" "results/${safe_domain}_waybackurls.txt" | sort -u -o "results/${safe_domain}_waybackurls.txt"

    echo "[+] [${raw_domain}] 🕷️ Katana 지능형 크롤링 준비..."
    cat "results/${safe_domain}_gau.txt" "results/${safe_domain}_waybackurls.txt" 2>/dev/null | sort -u > "results/${safe_domain}_raw_seed.txt"
    
    # 💡 OOM(메모리 초과) 방지 컷오프를 넉넉하게 상향 (50,000 -> 100,000)
    shuf -n 100000 "results/${safe_domain}_raw_seed.txt" -o "results/${safe_domain}_raw_seed.txt" 2>/dev/null || true
    uro -i "results/${safe_domain}_raw_seed.txt" -o "results/${safe_domain}_clean_seed.txt"

    # 💡 Katana 크롤링 시작점(Seed) 대폭 확대 (300 -> 1000)
    shuf -n 1000 "results/${safe_domain}_clean_seed.txt" > "results/${safe_domain}_katana_seed.txt" 2>/dev/null || cp "results/${safe_domain}_clean_seed.txt" "results/${safe_domain}_katana_seed.txt"

    # 💡 Katana Depth 증가(-d 4) 및 타임아웃 대폭 연장(30분)
    echo "  -> [Katana] Depth 4 딥 크롤링 시작 (최대 30분 타임아웃)..."
    timeout 30m katana -list "results/${safe_domain}_katana_seed.txt" -d 4 -jc -kf all -c 3 -rl 75 -ct 15 -silent > "results/${safe_domain}_katana.txt" 2>/dev/null
    grep -iE "$regex" "results/${safe_domain}_katana.txt" | sort -u -o "results/${safe_domain}_katana.txt"
    
    rm -f "results/${safe_domain}_raw_seed.txt" "results/${safe_domain}_clean_seed.txt" "results/${safe_domain}_katana_seed.txt"

    # 무의미한 오픈소스 JS 라이브러리를 강력한 정규식으로 차단하여 고가치 JS 파일만 추출
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
            
            # 💡 다운로드 한도를 1000개로 상향 조정
            local MAX_SUCCESS=1000
            local success_cnt=0
            local fail_cnt=0

            while read -r url; do
                [[ -z "$url" ]] && continue
                local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
                
                # 💡 JS 다운로드 타임아웃 5초로 수정 (connect 3초, max 5초)
                if curl -s -L --connect-timeout 3 --max-time 5 --fail \
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
# 가상머신 터짐(OOM) 방지를 위해 동시 실행 프로세스를 2개로 고정
xargs -P 2 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
