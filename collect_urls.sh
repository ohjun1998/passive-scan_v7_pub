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
        echo "[+] [${raw_domain}] 🔍 와일드카드 감지: Subfinder로 서브도메인을 전수조사한 후 아카이빙을 진행합니다."
        
        subfinder -d "$base_domain" -all -silent > "results/${safe_domain}_subs.txt"
        echo "$base_domain" >> "results/${safe_domain}_subs.txt"
        sort -u "results/${safe_domain}_subs.txt" -o "results/${safe_domain}_subs.txt"
        
        local sub_count=$(wc -l < "results/${safe_domain}_subs.txt")
        echo "  -> [Subfinder] 총 ${sub_count}개의 서브도메인을 발견했습니다."
        
        cat "results/${safe_domain}_subs.txt" | gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        cat "results/${safe_domain}_subs.txt" | waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    else
        echo "[+] [${raw_domain}] 🔍 단일 도메인 정찰을 시작합니다."
        echo "$base_domain" | gau > "results/${safe_domain}_gau.txt" 2>/dev/null
        echo "$base_domain" | waybackurls > "results/${safe_domain}_waybackurls.txt" 2>/dev/null
    fi

    grep -iE "$regex" "results/${safe_domain}_gau.txt" | sort -u -o "results/${safe_domain}_gau.txt"
    grep -iE "$regex" "results/${safe_domain}_waybackurls.txt" | sort -u -o "results/${safe_domain}_waybackurls.txt"

    # JS 파일만 추출
    cat "results/${safe_domain}_gau.txt" "results/${safe_domain}_waybackurls.txt" 2>/dev/null | grep -E '\.js($|\?)' 2>/dev/null | sort -u > "results/${safe_domain}_js_raw_list.txt"
    
    # URL을 절대 경로로 모두 변환
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
    echo "  -> [성공] 총 ${total_js}개의 자바스크립트(JS) 소스 경로를 식별했습니다."

    if [ "$total_js" -gt 0 ]; then
        if [ -f "global_js_db.txt" ]; then
            sort -u global_js_db.txt -o global_js_db_sorted.txt
            comm -23 "results/${safe_domain}_js_master_list.txt" global_js_db_sorted.txt > "results/${safe_domain}_js_new_list.txt"
        else
            cp "results/${safe_domain}_js_master_list.txt" "results/${safe_domain}_js_new_list.txt"
        fi

        local total_new_js=$(wc -l < "results/${safe_domain}_js_new_list.txt")
        echo "  -> [신규 JS 필터링] 과거 분석 이력을 제외한 ${total_new_js}개의 새로운 JS 파일을 발견했습니다."

        if [ "$total_new_js" -gt 0 ]; then
            local download_dir="results/${safe_domain}_js_files"
            mkdir -p "$download_dir"
            rm -f "results/${safe_domain}_js_mapping.txt"

            # 💡 [핵심 패치] 1000개로 자르지 않고, 전체 신규 리스트를 무작위로 섞기만 합니다.
            shuf "results/${safe_domain}_js_new_list.txt" > "results/${safe_domain}_js_urls_target.txt"
            
            local MAX_SUCCESS=1000
            local success_cnt=0
            local fail_cnt=0
            local attempt_cnt=0

            echo "  -> [스텔스 다운로드] 실패 건은 무시하고 성공 기준 ${MAX_SUCCESS}개를 채울 때까지 시도합니다..."

            while read -r url; do
                [[ -z "$url" ]] && continue
                ((attempt_cnt++))
                local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-150).js
                
                # 타임아웃 4초 내에 다운로드 성공 시에만 카운트 증가
                if curl -s -L --connect-timeout 2 --max-time 4 --fail \
                     -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                     "$url" -o "$download_dir/$safe_name"; then
                    
                    ((success_cnt++))
                    echo "    [✓] (성공: ${success_cnt}/${MAX_SUCCESS}) 타겟 다운로드 완료"
                    echo -e "${safe_name}\t${url}" >> "results/${safe_domain}_js_mapping.txt"
                    
                    # 💡 성공 횟수가 1000개(MAX_SUCCESS)에 도달하면 그 즉시 다운로드 루프를 강제 종료합니다.
                    if [ "$success_cnt" -ge "$MAX_SUCCESS" ]; then
                        echo "    [*] 목표 다운로드 수치(${MAX_SUCCESS}개) 달성! 스텔스 모드 종료."
                        break
                    fi
                else
                    # 실패 시 success_cnt는 그대로 두고 실패 건수만 올리며 다음 URL로 넘어갑니다.
                    ((fail_cnt++))
                    echo "    [✗] (실패 누적: ${fail_cnt}개) 연결 거부됨 - 다른 파일로 대체합니다."
                fi
                sleep 0.2
            done < "results/${safe_domain}_js_urls_target.txt"

            echo "  -> [작업 완료] 총 시도 횟수: ${attempt_cnt}번 | 최종 성공 확보: ${success_cnt}개 (실패/막힘: ${fail_cnt}개)"
        else
            echo "  -> [알림] 새로운 JS 파일이 없어 다운로드를 생략합니다. (모두 이미 분석 완료됨)"
        fi
    fi
}

export -f collect_master
echo "[*] 할당된 그룹($TARGET_FILE)에 대한 분산 수집을 시작합니다."
xargs -P 5 -n 1 -a "$TARGET_FILE" -I {} bash -c 'collect_master "{}"'

rm -f targets_group*
