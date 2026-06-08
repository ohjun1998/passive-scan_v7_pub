#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [Stage 1: Collector] Fetching passive URLs from APIs..."
    
    # 1. 아카이브 API 원천 징수 및 원본 백업
    echo "$domain" | gau > "results/${domain}_gau.txt" 2>/dev/null
    sort -u "results/${domain}_gau.txt" -o "results/${domain}_gau.txt"

    echo "$domain" | waybackurls > "results/${domain}_waybackurls.txt" 2>/dev/null
    sort -u "results/${domain}_waybackurls.txt" -o "results/${domain}_waybackurls.txt"

    # 2. 순수 .js 목록 추출 및 마스터 주소록 생성
    cat "results/${domain}_gau.txt" "results/${domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\\?)' 2>/dev/null | sort -u > "results/${domain}_js_master_list.txt"
    
    local total_js=$(wc -l < "results/${domain}_js_master_list.txt")
    echo "  -> [$domain] Successfully indexed $total_js unique JS targets."

    # 3. 타겟 서버 차단 방지를 위한 선행 다운로드 (최대 500개 제한)
    if [ "$total_js" -gt 0 ]; then
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"
        
        # 매핑 기록 파일 초기화
        rm -f "results/${domain}_js_mapping.txt"

        # 주소 형태 강제 복원 및 정제 (최대 500개 라인 추출)
        head -n 1500 "results/${domain}_js_master_list.txt" | while read -r url; do
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
        
        echo -n "[+] [$domain] Downloading targeting JS assets: "
        local success_cnt=0
        local fail_cnt=0

        while read -r url; do
            [[ -z "$url" ]] && continue
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            
            # 💡 [보안 강화] 외부인이 타겟 URL 주소를 보지 못하도록 콘솔에는 주소를 빼고 기호만 출력합니다.
            if curl -s -L --max-time 15 --fail \
                 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                 "$url" -o "$download_dir/$safe_name"; then
                echo -n "."  # 성공 시 점(.) 표기
                ((success_cnt++))
            else
                echo -n "x"  # 실패 시 x 표기
                ((fail_cnt++))
            fi
            sleep 0.5
        done < "results/${domain}_js_urls_shuffled.txt"
        echo "" # 줄바꿈

        rm -f "results/${domain}_js_urls_clean.txt" "results/${domain}_js_urls_shuffled.txt"
        echo "  -> [$domain] Batch completed. (Successfully Downloaded: ${success_cnt} / Failed: ${fail_cnt})"
    fi
}

export -f collect_master
echo "[*] Launching Stage 1 Master URL Collector & Downloader Matrix for $TARGET_FILE..."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
