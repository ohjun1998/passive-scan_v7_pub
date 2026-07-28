#!/bin/bash

# $1 인자가 없으면 기본값(00) 할당
GROUP=${1:-"00"}
TARGETS_FILE="targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "[-] $TARGETS_FILE 파일이 존재하지 않습니다."
  exit 1
fi

mkdir -p results
touch global_js_db.txt

echo "==================================================================="
echo "🚀 [Node-$GROUP] 정찰 파이프라인 가동 (선택적 Subfinder + Waybackurls + GAU + Katana)"
echo "==================================================================="

for DOMAIN in $(cat $TARGETS_FILE); do
  
  # ---------------------------------------------------------
  # 💡 0. 와일드카드(*.) 존재 여부 확인 및 분기 처리
  # ---------------------------------------------------------
  if [[ "$DOMAIN" == \*\.* ]]; then
    IS_WILDCARD=true
    # 앞의 '*. ' 제거 후 순수 도메인만 추출 (예: *.kakao.com -> kakao.com)
    SAFE_DOMAIN=$(echo "$DOMAIN" | sed 's/^\*\.//')
  else
    IS_WILDCARD=false
    SAFE_DOMAIN="$DOMAIN"
  fi

  echo ""
  echo "=================================================="
  if [ "$IS_WILDCARD" = true ]; then
    echo "🎯 [Target: $SAFE_DOMAIN] (와일드카드 ⭕) 서브도메인 확장 후 스캔 시작"
  else
    echo "🎯 [Target: $SAFE_DOMAIN] (단일 도메인 ❌) 지정된 도메인만 집중 스캔 시작"
  fi
  echo "=================================================="

  # ---------------------------------------------------------
  # 1. Subfinder (서브도메인 탐색 엔진) - 와일드카드일 때만 실행!
  # ---------------------------------------------------------
  if [ "$IS_WILDCARD" = true ]; then
    echo "  [+] 🌐 [Subfinder] 와일드카드 타겟 감지! 서브도메인 딥 스캔 가동 중..."
    subfinder -d $SAFE_DOMAIN -all -silent > results/${SAFE_DOMAIN}_subdomains.txt 2>/dev/null
    
    # 탐지된 서브도메인 + 원래의 메인 도메인을 하나로 합침
    echo $SAFE_DOMAIN >> results/${SAFE_DOMAIN}_subdomains.txt
    sort -u results/${SAFE_DOMAIN}_subdomains.txt > results/${SAFE_DOMAIN}_all_targets.txt
    
    SUB_COUNT=$(wc -l < results/${SAFE_DOMAIN}_all_targets.txt)
    echo "  [+] ✅ [Subfinder] 타겟 확장 완료: 총 ${SUB_COUNT}개의 서브/루트 도메인 묶음 확보!"
  else
    # 와일드카드가 아닐 경우, 단일 도메인 1개만 타겟 리스트에 넣음
    echo "  [+] 📌 단일 도메인 타겟 감지! 서브도메인 탐색을 건너뜁니다."
    echo $SAFE_DOMAIN > results/${SAFE_DOMAIN}_all_targets.txt
  fi

  # ---------------------------------------------------------
  # 2. Waybackurls (과거 아카이브 URL 병렬 추출)
  # ---------------------------------------------------------
  (
    echo "  [+] 🏛️ [Waybackurls] 과거 아카이브 URL 병렬 추출 중..."
    cat results/${SAFE_DOMAIN}_all_targets.txt | waybackurls > results/${SAFE_DOMAIN}_waybackurls_raw.txt 2>/dev/null

    if [ -s "results/${SAFE_DOMAIN}_waybackurls_raw.txt" ]; then
      cat results/${SAFE_DOMAIN}_waybackurls_raw.txt | uro > results/${SAFE_DOMAIN}_waybackurls.txt
      WAYBACK_COUNT=$(wc -l < results/${SAFE_DOMAIN}_waybackurls.txt)
      echo "  [+] 🔍 [Waybackurls] 완료: 총 ${WAYBACK_COUNT}개의 URL 확보"
    else
      echo "  [-] 🔍 [Waybackurls] 발견된 내역 없음"
      touch results/${SAFE_DOMAIN}_waybackurls.txt
    fi
    rm -f results/${SAFE_DOMAIN}_waybackurls_raw.txt
  ) &

  # ---------------------------------------------------------
  # 3. GAU (외부 위협 인텔리전스 기반)
  # ---------------------------------------------------------
  (
    echo "  [+] 🌐 [GAU] 외부 위협 인텔리전스 URL 수집 중..."
    cat results/${SAFE_DOMAIN}_all_targets.txt | gau --threads 5 > results/${SAFE_DOMAIN}_gau_raw.txt 2>/dev/null

    if [ -s "results/${SAFE_DOMAIN}_gau_raw.txt" ]; then
      cat results/${SAFE_DOMAIN}_gau_raw.txt | uro > results/${SAFE_DOMAIN}_gau.txt
      GAU_COUNT=$(wc -l < results/${SAFE_DOMAIN}_gau.txt)
      echo "  [+] 🔍 [GAU] 완료: 총 ${GAU_COUNT}개의 URL 확보"
    else
      echo "  [-] 🔍 [GAU] 발견된 내역 없음"
      touch results/${SAFE_DOMAIN}_gau.txt
    fi
    rm -f results/${SAFE_DOMAIN}_gau_raw.txt
  ) &

  # ---------------------------------------------------------
  # 4. Katana (스텔스 크롤링 - 확장된 타겟 리스트 활용)
  # ---------------------------------------------------------
  (
    echo "  [+] 🕷️ [Katana] 타겟 리스트 대상 스텔스 크롤링 가동..."
    katana -list results/${SAFE_DOMAIN}_all_targets.txt -d 2 -c 5 -rl 50 -jc -silent > results/${SAFE_DOMAIN}_katana_raw.txt 2>/dev/null

    if [ -s "results/${SAFE_DOMAIN}_katana_raw.txt" ]; then
      cat results/${SAFE_DOMAIN}_katana_raw.txt | uro > results/${SAFE_DOMAIN}_katana.txt
      KATANA_COUNT=$(wc -l < results/${SAFE_DOMAIN}_katana.txt)
      echo "  [+] 🔍 [Katana] 완료: 총 ${KATANA_COUNT}개의 고가치 경로 식별"
    else
      echo "  [-] 🔍 [Katana] 스텔스 크롤링 결과 없음"
      touch results/${SAFE_DOMAIN}_katana.txt
    fi
    rm -f results/${SAFE_DOMAIN}_katana_raw.txt
  ) &

  # ---------------------------------------------------------
  # ⚡ 3개의 스캐너가 모두 끝날 때까지 대기
  # ---------------------------------------------------------
  wait
  echo "  [*] ✅ 해당 도메인의 스캔(Waybackurls, GAU, Katana)이 병렬로 완료되었습니다!"

  # ---------------------------------------------------------
  # 5. JS 파일 추출 및 스마트 다운로드 (방어 로직)
  # ---------------------------------------------------------
  echo "  [+] ⚙️ 수집된 전체 데이터에서 JavaScript(JS) 타겟 추출 중..."
  cat results/${SAFE_DOMAIN}_*.txt | grep -iE '\.js($|\?)' | awk -F '?' '{print $1}' | sort -u > results/${SAFE_DOMAIN}_js_targets.txt
  JS_TOTAL=$(wc -l < results/${SAFE_DOMAIN}_js_targets.txt)

  if [ "$JS_TOTAL" -gt 0 ]; then
    echo "  [+] 💡 총 ${JS_TOTAL}개의 자바스크립트(JS) 소스 경로를 식별했습니다."

    # 이전에 분석한 JS 파일 제외 (스마트 필터링)
    grep -v -F -f global_js_db.txt results/${SAFE_DOMAIN}_js_targets.txt > results/${SAFE_DOMAIN}_js_new.txt 2>/dev/null || cat results/${SAFE_DOMAIN}_js_targets.txt > results/${SAFE_DOMAIN}_js_new.txt
    JS_NEW=$(wc -l < results/${SAFE_DOMAIN}_js_new.txt)

    echo "  [!] 🛡️ [중복 방지] 과거에 분석 완료된 파일 제외: ${JS_NEW}개의 신규 JS만 남았습니다."

    if [ "$JS_NEW" -gt 0 ]; then
      head -n 1000 results/${SAFE_DOMAIN}_js_new.txt > results/${SAFE_DOMAIN}_js_final.txt
      JS_FINAL=$(wc -l < results/${SAFE_DOMAIN}_js_final.txt)

      echo "  [!] 🛡️ [용량 보호] 디스크 과부하 및 타임아웃 방지를 위해 최대 ${JS_FINAL}개까지만 다운로드를 진행합니다."
      echo "  [+] 📥 JS 다운로드 병렬(10 Thread) 가동 중..."

      mkdir -p results/${SAFE_DOMAIN}_js_files
      cat results/${SAFE_DOMAIN}_js_final.txt | xargs -I {} -P 10 sh -c '
        url="{}"
        filename=$(basename "$url")
        curl -s -f -m 3 --create-dirs -o "results/'${SAFE_DOMAIN}'_js_files/$filename" "$url" && echo "$url" >> global_js_db.txt
      '

      DOWNLOADED=$(ls -1q results/${SAFE_DOMAIN}_js_files 2>/dev/null | wc -l)
      echo "  [+] ✅ 다운로드 성공: 총 ${DOWNLOADED} 개 확보 (404/403 에러 제외됨)"
    else
      echo "  [+] ✅ 다운로드할 신규 JS 파일이 없습니다. (모두 이미 분석됨)"
    fi
  else
    echo "  [-] 💡 식별된 JS 소스 경로가 없습니다."
  fi

done

echo "==================================================================="
echo "🏁 [Node-$GROUP] 도메인 수집 프로세스 종료"
echo "==================================================================="
