#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

# 💡 가상머신 20대 분산 폭격을 위한 타겟 리스트 20분할 보존
split -d -n l/20 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [Stage 1: Collector] Fetching passive URLs from APIs..."
    
    # [서브도메인 차단 필터] 타겟 도메인과 정확히 일치하는 주소만 추출
    echo "$domain" | gau | grep -iE "^https?://${domain}(/|$)" > "results/${domain}_gau.txt" 2>/dev/null
    sort -u "results/${domain}_gau.txt" -o "results/${domain}_gau.txt"

    echo "$domain" | waybackurls | grep -iE "^https?://${domain}(/|$)" > "results/${domain}_waybackurls.txt" 2>/dev/null
    sort -u "results/${domain}_waybackurls.txt" -o "results/${domain}_waybackurls.txt"

    cat "results/${domain}_gau.txt" "results/${domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\?)' 2>/dev/null | sort -u > "results/${domain}_js_master_list.txt"
    
    local total_js=$(wc -l < "results/${domain}_js_master_list.txt")
    echo "  -> [$domain] Successfully indexed $total_js unique strict JS targets."

    # 💡 [다운로드 제한 최적화] 타겟 서버 차단 방지를 위한 선행 다운로드 한계를 1000개로 조정
    if [ "$total_js" -gt 0 ]; then
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"
        
        rm -f "results/${domain}_js_mapping.txt"

        # 주소 형태 강제 복원 및 정제 (💡 최대 1000개 라인 추출로 제어)
        head -n 1000 "results/${domain}_js_master_list.txt" | while read -r url; do
            if [[ "$url" =~ ^https?:// ]]; then echo "$url"
            elif [[ "$url" =~ ^// ]]; then echo "https:$url"
            elif [[ "$url" =~ ^/ ]]; then echo "https://$domain$url"
            else echo "https://$domain/$url"
            fi
        done > "results/${domain}_js_urls_clean.txt"

        # [원본 주소 매핑 테이블 빌드]
        while read -r url; do
            [[ -z "$url" ]] && continue
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            echo -e "${safe_name}\t${url}" >> "results/${domain}_js_mapping.txt"
        done < "results/${domain}_js_urls_clean.txt"

        # 도메인 내부 요청을 무작위로 섞음
        shuf "results/${domain}_js_urls_clean.txt" -o "results/${domain}_js_urls_shuffled.txt"
        
        echo "[+] [$domain] Downloading targeting JS assets safely with advanced stealth speeds..."
        local success_cnt=0
        local fail_cnt=0
        local current=0
        local total_download=$(wc -l < "results/${domain}_js_urls_shuffled.txt")

        while read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            
            # 스텔스 유지 보안 규칙: 외부 노출을 막기 위해 로그에서 원본 $url을 완전히 제외하고 성공 유무만 사출
            # 1초 초고속 끊기(--connect-timeout 1) 설정 결합
            if curl -s -L --connect-timeout 1 --max-time 4 --fail \
                 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                 "$url" -o "$download_dir/$safe_name"; then
                echo "    [✓] [${domain}] (${current}/${total_download}) Download Success"
                ((success_cnt++))
            else
                echo "    [✗] [${domain}] (${current}/${total_download}) Download Failed"
                ((fail_cnt++))
            fi
            
            # 요청 간 휴식기 0.2초 스텔스 고속 설정 유지
            sleep 0.2
        done < "results/${domain}_js_urls_shuffled.txt"

        rm -f "results/${domain}_js_urls_clean.txt" "results/${domain}_js_urls_shuffled.txt"
        echo "  -> [$domain] Batch completed. (Successfully Downloaded: ${success_cnt} / Failed: ${fail_cnt})"
    fi
}

export -f collect_master
echo "[*] Launching Stage 1 Master URL Collector & Downloader Matrix for $TARGET_FILE..."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
