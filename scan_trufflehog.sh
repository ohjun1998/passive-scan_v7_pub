#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

scan_truffle() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    local master_list="results/${domain}_js_master_list.txt"

    if [ -s "$master_list" ]; then
        echo "[+] [$domain] [Stage 2: TruffleHog Worker] Sanitizing and preparing JS URLs..."
        
        local download_dir="results/${domain}_js_files"
        mkdir -p "$download_dir"
        
        # 상대 경로거나 http가 빠진 주소들을 완벽한 https:// URL로 정제 및 강제 복원
        head -n 50 "$master_list" | while read -r url; do
            if [[ "$url" =~ ^https?:// ]]; then
                echo "$url"
            elif [[ "$url" =~ ^// ]]; then
                echo "https:$url"
            elif [[ "$url" =~ ^/ ]]; then
                echo "https://$domain$url"
            else
                echo "https://$domain/$url"
            fi
        done > "results/${domain}_js_urls_clean.txt"

        # 정제된 주소가 진짜 존재하는지 확인 후 다운로드 실행
        if [ -s "results/${domain}_js_urls_clean.txt" ]; then
            echo "[+] [$domain] Downloading targeted JS assets safely..."
            
            # 에러를 유발하던 --copies=1 옵션을 완벽히 제거했습니다.
            wget -P "$download_dir" \
                 -i "results/${domain}_js_urls_clean.txt" \
                 --tries=1 \
                 --timeout=5 \
                 --wait=1 \
                 --random-wait \
                 --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" || true
            
            # 다운로드된 파일이 실제로 존재할 때만 TruffleHog 가동
            if [ "$(ls -A "$download_dir" 2>/dev/null)" ]; then
                echo "[+] [$domain] Running TruffleHog verified filesystem scan on $(ls "$download_dir" | wc -l) files..."
                trufflehog filesystem "$download_dir" --only-verified --plain 2>/dev/null > "results/${domain}_trufflehog.txt"
            else
                echo "  -> [$domain] Warning: Wget failed to download any files. Check target WAF or URLs."
                echo "" > "results/${domain}_trufflehog.txt"
            fi
        fi
        
        # 자원 파기 및 디스크 청소
        rm -rf "$download_dir"
        rm -f "results/${domain}_js_urls_clean.txt"
    else
        echo "  -> [$domain] No JS assets found from Stage 1 Index."
    fi
}

export -f scan_truffle
echo "[*] Launching Stage 2 TruffleHog Analyzer Matrix for $TARGET_FILE..."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'scan_truffle "{}"'

rm -f targets_group*
