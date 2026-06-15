#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/20 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local raw_domain=$(echo "$1" | xargs)
    [[ -z "$raw_domain" || "$raw_domain" =~ ^# ]] && return

    # 기본 변수 세팅
    local base_domain="$raw_domain"
    local safe_domain="$raw_domain"
    local regex="^https?://${raw_domain//./\.}(/|$)"

    if [[ "$raw_domain" == \** ]]; then
        base_domain="${raw_domain#\*.}"
        safe_domain="wild_${base_domain}"
        regex="^https?://([a-zA-Z0-9.-]+\.)?${base_domain//./\.}(/|$)"
        echo "[+] [${raw_domain}] 🔍 와일드카드 감지: 루트 도메인($base_domain)과 서브도메인을 동시에 긁어옵니다."
        
        # 💡 [핵심 최적화] 아카이브 누락 방지를 위해 루트 도메인과 와일드카드 도메인을 동시에 질의하여 병합
        (echo "$base_domain"; echo "*.$base_domain") | gau --subs > "results/${safe_domain}_gau.txt" 2>/dev/null
        (echo "$base_domain"; echo "*.$base_domain") | waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    else
        echo "[+] [${raw_domain}] 🔍 단일 도메인 감지: 서브도메인을 엄격히 차단하고 정찰합니다."
        
        echo "$base_domain" | gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        echo "$base_domain" | waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    fi

    # 정규식(Regex)을 통한 확실한 필터링 및 중복 제거
    grep -iE "$regex" "results/${safe_domain}_gau.txt" | sort -u -o "results/${safe_domain}_gau.txt"
    grep -iE "$regex" "results/${safe_domain}_waybackurls.txt" | sort -u -o "results/${safe_domain}_waybackurls.txt"

    # JS 파일만 추출
    cat "results/${safe_domain}_gau.txt" "results/${safe_domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\?)' 2>/dev/null | sort -u > "results/${safe_domain}_js_master_list.txt"
    
    local total_js=$(wc -l < "results/${safe_domain}_js_master_list.txt")
    echo "  -> [성공] 총 ${total_js}개의 자바스크립트(JS) 소스 경로를 식별했습니다."

    # 실물 소스코드 다운로드 파트 (1000개 제한)
    if [ "$total_js" -gt 0 ]; then
        local download_dir="results/${safe_domain}_js_files"
        mkdir -p "$download_dir"
        rm -f "results/${safe_domain}_js_mapping.txt"

        head -n 1000 "results/${safe_domain}_js_master_list.txt" | while read -r url; do
            if [[ "$url" =~ ^https?:// ]]; then echo "$url"
            elif [[ "$url" =~ ^// ]]; then echo "https:$url"
            elif [[ "$url" =~ ^/ ]]; then echo "https://$base_domain$url"
            else echo "https://$base_domain/$url"
            fi
        done > "results/${safe_domain}_js_urls_clean.txt"

        while read -r url; do
            [[ -z "$url" ]] && continue
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            echo -e "${safe_name}\t${url}" >> "results/${safe_domain}_js_mapping.txt"
        done < "results/${safe_domain}_js_urls_clean.txt"

        shuf "results/${safe_domain}_js_urls_clean.txt" -o "results/${safe_domain}_js_urls_shuffled.txt"
        
        echo "  -> [스텔스 다운로드] 방화벽 우회 모드로 타겟 코드를 안전하게 가져옵니다..."
        local success_cnt=0
        local fail_cnt=0
        local current=0
        local total_download=$(wc -l < "results/${safe_domain}_js_urls_shuffled.txt")

        while read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            
            if curl -s -L --connect-timeout 1 --max-time 4 --fail \
                 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                 "$url" -o "$download_dir/$safe_name"; then
                echo "    [✓] (${current}/${total_download}) 다운로드 성공"
                ((success_cnt++))
            else
                echo "    [✗] (${current}/${total_download}) 다운로드 실패 (막힘/삭제됨)"
                ((fail_cnt++))
            fi
            sleep 0.2
        done < "results/${safe_domain}_js_urls_shuffled.txt"

        rm -f "results/${safe_domain}_js_urls_clean.txt" "results/${safe_domain}_js_urls_shuffled.txt"
        echo "  -> [작업 완료] 파일 실물 확보: ${success_cnt}개 (실패: ${fail_cnt}개)"
    fi
}

export -f collect_master
echo "[*] 할당된 그룹($TARGET_FILE)에 대한 분산 수집을 시작합니다."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
