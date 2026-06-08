#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

collect_master() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [Stage 1: Collector] Fetching passive URLs from APIs..."
    
    # 1. 아카이브 API 원천 징수 및 원본 백업 (엑셀 리포터 분석용)
    echo "$domain" | gau > "results/${domain}_gau.txt" 2>/dev/null
    sort -u "results/${domain}_gau.txt" -o "results/${domain}_gau.txt"

    echo "$domain" | waybackurls > "results/${domain}_waybackurls.txt" 2>/dev/null
    sort -u "results/${domain}_waybackurls.txt" -o "results/${domain}_waybackurls.txt"

    # 2. 두 파일에서 중복 없는 깨끗한 순수 .js 목록만 추출하여 마스터 주소록 생성
    cat "results/${domain}_gau.txt" "results/${domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\?)' 2>/dev/null | sort -u > "results/${domain}_js_master_list.txt"
    
    local total_js=$(wc -l < "results/${domain}_js_master_list.txt")
    echo "  -> [$domain] Successfully indexed $total_js unique JS targets."

    # 3. [최적화 핵심] 타겟 서버 차단 방지를 위한 선행 다운로드 (최대 200개 제한으로 확장)
    if [ "$total_js" -gt 0 ]; then
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"

        # 주소 형태 강제 복원 및 정제 (최대 200개 라인 추출)
        head -n 200 "results/${domain}_js_master_list.txt" | while read -r url; do
            if [[ "$url" =~ ^https?:// ]]; then echo "$url"
            elif [[ "$url" =~ ^// ]]; then echo "https:$url"
            elif [[ "$url" =~ ^/ ]]; then echo "https://$domain$url"
            else echo "https://$domain/$url"
            fi
        done > "results/${domain}_js_urls_clean.txt"

        # [WAF 차단 우회] 도메인 내부 요청을 무작위로 섞음
        shuf "results/${domain}_js_urls_clean.txt" -o "results/${domain}_js_urls_shuffled.txt"
        
        echo "[+] [$domain] Downloading targeting JS assets safely with delays..."
        while read -r url; do
            [[ -z "$url" ]] && continue
            local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
            
            # 브라우저 위장 및 패킷 지연 수집
            curl -s -L --max-time 15 \
                 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                 "$url" -o "$download_dir/$safe_name" || true
            sleep 0.5
        done < "results/${domain}_js_urls_shuffled.txt"

        rm -f "results/${domain}_js_urls_clean.txt" "results/${domain}_js_urls_shuffled.txt"
        echo "  -> [$domain] Done. Pre-downloaded $(ls "$download_dir" | wc -l) files for analysis stages."
    fi
}

export -f collect_master
echo "[*] Launching Stage 1 Master URL Collector & Downloader Matrix for $TARGET_FILE..."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
