#!/usr/bin/env python3
import os
import glob
import re
import json
import posixpath
import sqlite3
import shutil
import asyncio
import aiohttp
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qsl
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def escape_formula(value):
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')): return "'" + value
    return value

def make_absolute(url, domain):
    if url.startswith('http://') or url.startswith('https://'): return url
    elif url.startswith('//'): return f"https:{url}"
    elif url.startswith('/'): return f"https://{domain}{url}"
    else: return f"https://{domain}/{url}"

def get_status_color(status):
    status_str = str(status)
    if status_str.startswith('2'): return '28A745'
    if status_str.startswith('3'): return '17A2B8'
    if status_str.startswith('4'): return 'FD7E14'
    if status_str.startswith('5'): return 'DC3545'
    if 'Static' in status_str: return 'A8B8D0'
    if 'Skipped' in status_str: return 'E83E8C' 
    if 'Legacy' in status_str: return '6C757D'
    return '6C757D'

def get_status_priority(status):
    s = str(status)
    if s.startswith('2'): return 1
    if s.startswith('5'): return 2
    if s in ['401', '403']: return 3
    if s.startswith('3'): return 4
    if s.startswith('4'): return 5
    return 6

def get_safe_domain(target):
    return "wild_" + target[2:] if target.startswith('*.') else target

def normalize_dynamic_path(path):
    p = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '{UUID}', path)
    p = re.sub(r'\b\d{3,}\b', '{ID}', p)
    p = re.sub(r'\b[a-zA-Z0-9]{10,}\b', '{HASH}', p)
    return p

regex_sensitive_exts = re.compile(r'\.(env|bak|swp|old|sql|sqlite|db|dump|log|config|properties|yml|yaml|ini)$', re.IGNORECASE)
regex_sensitive_paths = re.compile(r'/(admin|administrator|wp-admin|manage|phpmyadmin|server-status|server-info|actuator|swagger-ui|graphql)($|/)', re.IGNORECASE)
regex_credential_params = re.compile(r'(?:\?|&)(api_?key|token|jwt|auth|secret|password|pwd|access_?token)=([a-zA-Z0-9\-_\.]{8,})', re.IGNORECASE)
regex_infra_paths = re.compile(r'/\.(git|svn|hg|aws|ssh|docker)($|/)', re.IGNORECASE)

def get_best_gemini_model(api_key):
    print("[*] 현재 API 키로 사용 가능한 최적의 Gemini AI 모델을 동적으로 탐색합니다...", flush=True)
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            models = res.json().get('models', [])
            valid_models = [m['name'] for m in models if 'generateContent' in m.get('supportedGenerationMethods', [])]
            
            priorities = [
                'models/gemini-1.5-flash-latest', 
                'models/gemini-2.5-flash',
                'models/gemini-1.5-flash', 
                'models/gemini-pro'
            ]
            
            for p in priorities:
                if p in valid_models:
                    selected = p.replace('models/', '')
                    print(f"[+] API 승인 확인! 타격 모델 설정 완료: {selected}", flush=True)
                    return selected
            
            if valid_models:
                best = valid_models[0].replace('models/', '')
                print(f"[+] API 승인 확인! 대체 모델 설정 완료: {best}", flush=True)
                return best
    except Exception as e:
        print(f"[-] 모델 동적 탐색 실패: {e}")
    
    print("[!] 탐색 실패. 강제로 gemini-1.5-flash 모델로 돌파합니다.")
    return "gemini-1.5-flash"

async def ask_gemini_async(session, gemini_key, batch, model_name):
    prompt = (
        "You are an elite Bug Bounty Hunter and Red Teamer. Analyze the following list of URLs discovered during reconnaissance.\n"
        "Evaluate the probability (0 to 100) that each URL contains a security vulnerability (such as IDOR, SSRF, SQLi, Privilege Escalation, Command Injection, or Sensitive Information Disclosure) based on its paths, parameters, and naming conventions.\n"
        "Return EXACTLY a JSON array of objects. Do not include markdown formatting or backticks. Each object must contain these keys:\n"
        "- 'url': the exact URL string\n"
        "- 'probability': integer from 0 to 100\n"
        "- 'vuln_type': string of suspected vulnerability type\n"
        "- 'reason': short clear explanation in Korean of why this URL is high risk and how to test it.\n\n"
        f"URLs:\n{json.dumps(batch)}"
    )
    g_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"}
    }
    
    timeout = aiohttp.ClientTimeout(total=150)
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            async with session.post(g_api_url, json=payload, timeout=timeout) as res:
                if res.status == 200:
                    res_json = await res.json()
                    raw_reply = res_json.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
                    
                    if not raw_reply: return []
                        
                    match = re.search(r'\[\s*\{.*?\}\s*\]', raw_reply, re.DOTALL)
                    if match:
                        try: return json.loads(match.group(0))
                        except: pass
                    
                    try: return json.loads(raw_reply.strip())
                    except: return []
                
                elif res.status == 429:
                    print(f"[-] API 트래픽 제한(429). 10초 대기 후 재시도... ({attempt+1}/{max_retries})")
                    await asyncio.sleep(10)
                    continue
                else:
                    error_msg = await res.text()
                    print(f"[-] Gemini API 통신 에러 ({res.status}): {error_msg}")
                    return []
                    
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                print(f"[-] API 타임아웃. 재시도 중... ({attempt+1}/{max_retries})")
                await asyncio.sleep(3)
                continue
            else:
                print("[-] Gemini API 최종 타임아웃 발생.")
        except Exception as e:
            print(f"[-] Gemini 요청 실패: {str(e)}")
            return []
            
    return []

async def process_all_gemini(gemini_key, candidate_urls, model_name):
    ai_ranked_results = []
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(candidate_urls), 10):
            batch = candidate_urls[i:i+10]
            print(f"[*] Gemini AI 지능형 분석 진행 중... ({i+1} ~ {min(i+10, len(candidate_urls))} / {len(candidate_urls)})")
            
            res_list = await ask_gemini_async(session, gemini_key, batch, model_name)
            if isinstance(res_list, list):
                ai_ranked_results.extend(res_list)
            
            if i + 10 < len(candidate_urls):
                await asyncio.sleep(3)
                
    return ai_ranked_results

def build_advanced_excel_report():
    print("[+] 초고속 SQLite DB 기반 차분 분석(Differential Analysis) 엔진 가동 중...", flush=True)
    if not os.path.exists('targets.txt'): return
    with open('targets.txt', 'r') as f: targets = [line.strip() for line in f if line.strip()]

    target_map = {get_safe_domain(t): t for t in targets}
    
    os.makedirs('reports', exist_ok=True)
    db_path = 'reports/recon_history.db'
    prev_db_path = 'previous_report/recon_history.db'
    
    if os.path.exists(prev_db_path):
        shutil.copy(prev_db_path, db_path)
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS master_urls (url TEXT PRIMARY KEY)")
    cursor.execute("CREATE TABLE IF NOT EXISTS downloaded_js (url TEXT PRIMARY KEY)")
    cursor.execute("CREATE TABLE IF NOT EXISTS historical_subdomains (subdomain TEXT PRIMARY KEY)")
    
    # 💡 [핵심 패치 1] 영구적으로 깎이지 않는 '진짜 누적' 데이터를 보관하는 테이블 신설
    cursor.execute('''CREATE TABLE IF NOT EXISTS target_stats (
        target TEXT PRIMARY KEY,
        passive_tot INTEGER DEFAULT 0,
        jsluice_tot INTEGER DEFAULT 0,
        katana_tot INTEGER DEFAULT 0
    )''')
    conn.commit()

    js_url_converter = {}
    today_downloaded_js = set()
    for mf in glob.glob('results/*_js_mapping.txt'):
        try:
            with open(mf, 'r', errors='ignore') as f:
                for line in f:
                    if '\t' in line:
                        s, o = line.strip().split('\t', 1)
                        js_url_converter[s] = o
                        today_downloaded_js.add(o)
        except: pass

    if today_downloaded_js:
        cursor.executemany("INSERT OR IGNORE INTO downloaded_js (url) VALUES (?)", [(u,) for u in today_downloaded_js])
        conn.commit()

    cursor.execute("SELECT subdomain FROM historical_subdomains")
    previous_subdomains = {row[0] for row in cursor.fetchall()}

    matrix_data = {raw_target: {} for raw_target in targets}
    signature_counts = {}
    
    junk_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.eot', '.ttf', '.mp4')
    blacklist_words = ['logout', 'signout', 'delete', 'remove', 'revoke', 'destroy']
    
    all_today_raw_urls = []
    temp_file_records = []

    for file_path in glob.glob('results/*.*'):
        filename = os.path.basename(file_path).lower()
        match = re.match(r'^(.*)_(linkfinder|trufflehog|gau|waybackurls|katana)\.txt$', filename)
        if not match: continue
        
        safe_domain = match.group(1)
        if safe_domain not in target_map: continue
        
        raw_target = target_map[safe_domain]
        is_wildcard = raw_target.startswith('*.')
        base_domain = raw_target[2:] if is_wildcard else raw_target

        if 'linkfinder' in filename or 'jsluice' in filename: source_tool = 'LinkFinder'
        elif 'trufflehog' in filename: source_tool = 'TruffleHog'
        elif 'waybackurls' in filename: source_tool = 'Waybackurls'
        elif 'gau' in filename: source_tool = 'GAU'
        elif 'katana' in filename: source_tool = 'Katana'
        else: continue

        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str.startswith('#'): continue
                    line_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', line_str)
                    if not line_str: continue
                    
                    if '\t' in line_str: js_file, raw_url = line_str.split('\t', 1)
                    else: js_file, raw_url = "Passive Archive", line_str
                    
                    if js_file in js_url_converter: js_file = js_url_converter[js_file]
                    
                    abs_url = make_absolute(raw_url, base_domain)
                    parsed_netloc = urlparse(abs_url).netloc.split(':')[0]
                    
                    if is_wildcard:
                        if not (parsed_netloc == base_domain or parsed_netloc.endswith('.' + base_domain)): continue
                    else:
                        if parsed_netloc != base_domain: continue

                    if urlparse(abs_url).path.lower().endswith(junk_extensions): continue
                    
                    all_today_raw_urls.append(abs_url)
                    temp_file_records.append((raw_target, abs_url, source_tool, js_file))
        except: pass

    existing_urls_cache = set()
    all_today_raw_urls = list(set(all_today_raw_urls))
    
    for idx in range(0, len(all_today_raw_urls), 500):
        chunk = all_today_raw_urls[idx:idx+500]
        placeholders = ",".join(["?"] * len(chunk))
        cursor.execute(f"SELECT url FROM master_urls WHERE url IN ({placeholders})", chunk)
        for row in cursor.fetchall():
            existing_urls_cache.add(row[0])

    for raw_target, abs_url, source_tool, js_file in temp_file_records:
        parsed_for_sig = urlparse(abs_url)
        query_keys = tuple(sorted([k for k, v in parse_qsl(parsed_for_sig.query, keep_blank_values=True)]))
        norm_path = normalize_dynamic_path(parsed_for_sig.path)
        signature = (parsed_for_sig.netloc, posixpath.dirname(norm_path), posixpath.splitext(norm_path)[1], query_keys)

        if abs_url not in matrix_data[raw_target]:
            if signature_counts.get(signature, 0) >= 5: continue
            signature_counts[signature] = signature_counts.get(signature, 0) + 1
            
            is_new = abs_url not in existing_urls_cache
            matrix_data[raw_target][abs_url] = {"tools": set(), "files": set(), "is_new": is_new}
            
        matrix_data[raw_target][abs_url]["tools"].add(source_tool)
        if source_tool in ['LinkFinder', 'TruffleHog']:
            matrix_data[raw_target][abs_url]["files"].add(js_file)

    status_codes = {}
    for res_file in glob.glob('results/httpx_results_*.json'):
        try:
            with open(res_file, 'r', errors='ignore') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line.strip())
                    status_codes[data.get('url')] = data.get('status_code', 'Dead')
        except: pass

    nuclei_findings = {}
    for res_file in glob.glob('results/nuclei_results_*.json'):
        try:
            with open(res_file, 'r', errors='ignore') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line.strip())
                    url = data.get('matched-at', data.get('host', ''))
                    if url:
                        if url not in nuclei_findings: nuclei_findings[url] = []
                        nuclei_findings[url].append(f"[{data.get('info', {}).get('severity', 'INFO').upper()}] {data.get('info', {}).get('name', 'Unknown')}")
        except: pass

    gemini_key = os.environ.get('GEMINI_API_KEY')
    ai_ranked_results = []
    
    if gemini_key:
        candidate_urls = []
        for url_map in matrix_data.values():
            for url, data in url_map.items():
                sc = str(status_codes.get(url, 'Dead'))
                if url in nuclei_findings or 'TruffleHog' in data["tools"] or sc in ['200', '301', '302', '401', '403', '500'] or '?' in url:
                    candidate_urls.append(url)
                    
        candidate_urls = list(set(candidate_urls))[:300]
        if candidate_urls:
            selected_model = get_best_gemini_model(gemini_key)
            print(f"[+] 총 {len(candidate_urls)}개의 핵심 엔드포인트를 식별하여 AI 추론을 요청합니다...")
            ai_ranked_results = asyncio.run(process_all_gemini(gemini_key, candidate_urls, selected_model))
            
            if ai_ranked_results:
                ai_ranked_results.sort(key=lambda x: x.get('probability', 0), reverse=True)
                print(f"[+] Gemini 분석 완료! {len(ai_ranked_results)}개 표적 시트 작성 준비.")
            else:
                print("[-] 구글 API 응답 에러로 인해 반환된 데이터가 없습니다.")

    now_str = datetime.now().strftime("%Y%m%d_%H%M")
    
    postman_collection = {
        "info": {
            "name": f"🎯 Passive Recon Master API Collection ({now_str})",
            "description": "자동 생성된 도메인별 API 및 엔드포인트 명세서입니다. Burp Suite의 OpenAPI Parser나 Postman에 Import하여 즉시 Fuzzing에 활용하세요.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": []
    }

    wb = Workbook()
    font_header, fill_header = Font(name='Malgun Gothic', bold=True, color='FFFFFF'), PatternFill(start_color='2F3542', end_color='2F3542', fill_type='solid')
    font_data, fill_zebra = Font(name='Malgun Gothic', size=10, color='333333'), PatternFill(start_color='F8F9FA', end_color='F8F9FA', fill_type='solid')
    align_center, align_left = Alignment(horizontal='center', vertical='center'), Alignment(horizontal='left', vertical='center')
    thin_border = Border(left=Side(style="thin", color="E0E0E0"), right=Side(style="thin", color="E0E0E0"), top=Side(style="thin", color="E0E0E0"), bottom=Side(style="thin", color="E0E0E0"))

    ws_dash = wb.active
    ws_dash.title = "Summary Dashboard"
    
    dash_headers = [
        "No", "타겟 도메인", "🌟 신규 서브", "📊 누적 / 🔥 신규 URL", 
        "jsluice (누적 / 신규)", "Katana (누적 / 신규)", 
        "🔥 Nuclei 탐지", "TruffleHog 탐지", 
        "🟢 200 (OK)", "🟠 403/401 (권한)", "🔴 500대 (에러)"
    ]
    ws_dash.append(dash_headers)
    for c in range(1, len(dash_headers) + 1): 
        ws_dash.cell(1, c).font = font_header; ws_dash.cell(1, c).fill = fill_header
        ws_dash.cell(1, c).alignment = align_center; ws_dash.cell(1, c).border = thin_border

    if ai_ranked_results:
        ws_ai = wb.create_sheet(title="🔮 Gemini AI Ranking")
        ws_ai.append(["🔙 대시보드로 돌아가기 (Return to Dashboard)"])
        ws_ai.merge_cells('A1:E1')
        back_cell_ai = ws_ai.cell(row=1, column=1)
        back_cell_ai.hyperlink = "#'Summary Dashboard'!A1"
        back_cell_ai.font = Font(name='Malgun Gothic', size=11, bold=True, color='0056B3', underline='single')
        back_cell_ai.fill = PatternFill(start_color='E9ECEF', end_color='E9ECEF', fill_type='solid')
        back_cell_ai.alignment = align_left
        
        ws_ai.append(["No", "🔮 취약점 발생 확률", "예상 취약점 분류", "타겟 절대 경로 (URL)", "Gemini AI 지능형 헌팅 가이드 심층 분석"])
        for c in range(1, 6):
            ws_ai.cell(2, c).font = font_header; ws_ai.cell(2, c).fill = PatternFill(start_color='4B0082', end_color='4B0082', fill_type='solid')
            ws_ai.cell(2, c).alignment = align_center; ws_ai.cell(2, c).border = thin_border
            
        for ai_idx, res in enumerate(ai_ranked_results, 1):
            prob = res.get('probability', 0)
            ws_ai.append([ai_idx, f"{prob}%", res.get('vuln_type', '-'), escape_formula(res.get('url', '-')), res.get('reason', '-')])
            fill_color = 'FFD2D2' if prob >= 80 else ('FFE4C4' if prob >= 50 else 'F8F9FA')
            for c in range(1, 6):
                cell = ws_ai.cell(ai_idx + 2, c)
                cell.font = font_data; cell.border = thin_border; cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type='solid')
                if c == 2: cell.font = Font(name='Malgun Gothic', bold=True, color='DC3545' if prob>=50 else '333333'); cell.alignment = align_center
                elif c in [4, 5]: cell.alignment = align_left
                else: cell.alignment = align_center

    ws_high = wb.create_sheet(title="High Risk Targets")
    ws_high.append(["🔙 대시보드로 돌아가기 (Return to Dashboard)"])
    ws_high.merge_cells('A1:I1')
    back_cell_h = ws_high.cell(row=1, column=1)
    back_cell_h.hyperlink = "#'Summary Dashboard'!A1"
    back_cell_h.font = Font(name='Malgun Gothic', size=11, bold=True, color='0056B3', underline='single')
    back_cell_h.fill = PatternFill(start_color='E9ECEF', end_color='E9ECEF', fill_type='solid')
    back_cell_h.alignment = align_left

    ws_high.append(["No", "🔥 신규여부", "🌟 신규 서브", "소스 출처", "발견된 JS 파일명", "응답 상태", "도메인", "고위험 경로 (Endpoint)", "탐지 사유"]) 
    for c in range(1, 10): ws_high.cell(2, c).font = font_header; ws_high.cell(2, c).fill = fill_header; ws_high.cell(2, c).alignment = align_center; ws_high.cell(2, c).border = thin_border

    dash_idx = 2
    all_today_discovered_urls = []
    high_risk_records = []
    
    # 💡 [핵심 패치 2] 글로벌 총계 합계를 위한 파이썬 내부 변수 (엑셀 SUM 에러 방어)
    g_passive_tot = g_passive_new = 0
    g_jsluice_tot = g_jsluice_new = 0
    g_katana_tot = g_katana_new = 0
    g_nuc = g_truf = g_200 = g_40x = g_50x = 0

    for raw_target, url_map in matrix_data.items():
        if not url_map: continue
        sheet_title = re.sub(r'[\\/\?\*\:\[\]]', '_', raw_target)[:30]
        
        postman_folder = {"name": raw_target, "item": []}
        
        # 오늘 발견한 전체 개수 및 신규 개수 파악
        today_passive_count = len(url_map)
        domain_new_count = sum(1 for data in url_map.values() if data.get("is_new", False))
        
        today_jsluice_total = sum(1 for data in url_map.values() if 'LinkFinder' in data["tools"])
        jsluice_new = sum(1 for data in url_map.values() if 'LinkFinder' in data["tools"] and data.get("is_new", False))
        
        today_katana_total = sum(1 for data in url_map.values() if 'Katana' in data["tools"])
        katana_new = sum(1 for data in url_map.values() if 'Katana' in data["tools"] and data.get("is_new", False))
        
        trufflehog_count = sum(1 for data in url_map.values() if 'TruffleHog' in data["tools"])
        nuclei_count = sum(1 for u in url_map.keys() if u in nuclei_findings)

        # 💡 [핵심 패치 3] SQLite DB에서 진짜 누적 데이터를 불러오고 업데이트
        cursor.execute("SELECT passive_tot, jsluice_tot, katana_tot FROM target_stats WHERE target = ?", (raw_target,))
        row = cursor.fetchone()
        
        if row:
            db_passive_tot, db_jsluice_tot, db_katana_tot = row
            # 기존 누적 데이터에 '오늘 발견한 신규 개수'를 무조건 더해서 업데이트!
            new_passive_tot = db_passive_tot + domain_new_count
            new_jsluice_tot = db_jsluice_tot + jsluice_new
            new_katana_tot = db_katana_tot + katana_new
        else:
            # 처음 스캔하는 도메인이면 오늘 발견한 총량을 누적의 베이스라인으로 삼음
            new_passive_tot = today_passive_count
            new_jsluice_tot = today_jsluice_total
            new_katana_tot = today_katana_total
            
        # 업데이트된 진짜 누적치를 DB에 저장
        cursor.execute("INSERT OR REPLACE INTO target_stats (target, passive_tot, jsluice_tot, katana_tot) VALUES (?, ?, ?, ?)", 
                       (raw_target, new_passive_tot, new_jsluice_tot, new_katana_tot))

        count_200 = count_40x = count_50x = 0
        for url in url_map.keys():
            all_today_discovered_urls.append(url)
            status = str(status_codes.get(url, 'Dead'))
            if status.startswith('2'): count_200 += 1
            elif status in ['401', '403']: count_40x += 1
            elif status.startswith('5'): count_50x += 1

        current_subdomains = {urlparse(u).netloc for u in url_map.keys()}
        new_subdomains = current_subdomains - previous_subdomains
        sub_dash_mark = "🌟 신규" if (bool(new_subdomains) and bool(previous_subdomains)) else "-"
        
        # 총계 변수 업데이트
        g_passive_tot += new_passive_tot
        g_passive_new += domain_new_count
        g_jsluice_tot += new_jsluice_tot
        g_jsluice_new += jsluice_new
        g_katana_tot += new_katana_tot
        g_katana_new += katana_new
        g_nuc += nuclei_count
        g_truf += trufflehog_count
        g_200 += count_200
        g_40x += count_40x
        g_50x += count_50x
        
        # 대시보드 열 추가
        ws_dash.append([
            dash_idx - 1, 
            escape_formula(raw_target), 
            sub_dash_mark, 
            f"{new_passive_tot} / {domain_new_count}", 
            f"{new_jsluice_tot} / {jsluice_new}", 
            f"{new_katana_tot} / {katana_new}", 
            nuclei_count, 
            trufflehog_count, 
            count_200, 
            count_40x, 
            count_50x
        ])
        
        for c in range(1, len(dash_headers) + 1):
            cell = ws_dash.cell(dash_idx, c)
            cell.font = font_data; cell.border = thin_border
            if c == 2: cell.hyperlink = f"#'{sheet_title}'!A1"; cell.font = Font(name='Malgun Gothic', color='0056B3', underline='single')
            elif c == 3 and sub_dash_mark == "🌟 신규": cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            
            # 신규가 있으면 핑크색 하이라이트
            if c == 4 and domain_new_count > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            elif c == 5 and jsluice_new > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            elif c == 6 and katana_new > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            elif c in [7, 8] and isinstance(cell.value, int) and cell.value > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
        dash_idx += 1

        ws = wb.create_sheet(title=sheet_title)
        ws.append(["🔙 대시보드로 돌아가기 (Return to Dashboard)"])
        ws.merge_cells('A1:G1')
        back_cell = ws.cell(row=1, column=1)
        back_cell.hyperlink = "#'Summary Dashboard'!A1"; back_cell.font = Font(name='Malgun Gothic', size=11, bold=True, color='0056B3', underline='single')
        back_cell.fill = PatternFill(start_color='E9ECEF', end_color='E9ECEF', fill_type='solid'); back_cell.alignment = align_left

        ws.append(["No", "🔥 신규여부", "🌟 신규 서브", "소스 출처", "발견된 JS 파일명", "응답 상태", "타겟 절대 경로 (URL)"])
        for c in range(1, 8): ws.cell(2, c).font = font_header; ws.cell(2, c).fill = fill_header; ws.cell(2, c).alignment = align_center; ws.cell(2, c).border = thin_border

        sorted_urls = sorted(url_map.items(), key=lambda x: (
            not x[1].get("is_new", False), 
            get_status_priority(status_codes.get(x[0], 'Dead') if any(b not in x[0].lower() for b in blacklist_words) else 'Skipped(위험)'), 
            x[0]
        ))
        
        for sub_idx, (url, data) in enumerate(sorted_urls, 1):
            if sub_idx > 1048500: break
            tools_str, files_str = ", ".join(sorted(list(data["tools"]))), ", ".join(sorted(list(data["files"]))) if data["files"] else "-"
            is_new_mark = "🆕 NEW" if data.get("is_new", False) else "-"
            is_blacklist = any(b in url.lower() for b in blacklist_words)
            
            if not is_blacklist:
                parsed_pm = urlparse(url)
                postman_folder["item"].append({"name": parsed_pm.path if parsed_pm.path else "/", "request": {"method": "GET", "header": [], "url": {"raw": url, "protocol": parsed_pm.scheme, "host": parsed_pm.netloc.split('.'), "path": [p for p in parsed_pm.path.split('/') if p], "query": [{"key": k, "value": v} for k, v in parse_qsl(parsed_pm.query, keep_blank_values=True)]}}})

            current_status = "Skipped(위험)" if is_blacklist else ( "Static(생략)" if urlparse(url).path.lower().endswith(junk_extensions) else status_codes.get(url, 'Dead') )
            is_new_subdomain = (urlparse(url).netloc in new_subdomains) and bool(previous_subdomains)
            sub_mark = "🌟 신규" if is_new_subdomain else "-"

            ws.append([sub_idx, is_new_mark, sub_mark, escape_formula(tools_str), escape_formula(files_str), current_status, escape_formula(url)])
            for c in range(1, 8):
                cell = ws.cell(sub_idx + 2, c)
                cell.font = font_data; cell.border = thin_border
                if ((sub_idx+2) % 2) == 1: cell.fill = fill_zebra
                if c == 2 and data.get("is_new", False): cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                if c == 3 and is_new_subdomain: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                if c == 6: cell.fill = PatternFill(start_color=get_status_color(current_status), end_color=get_status_color(current_status), fill_type='solid'); cell.font = Font(name='Malgun Gothic', bold=True, color='FFFFFF'); cell.alignment = align_center
                elif c in [4, 5, 7]: cell.alignment = align_left
                else: cell.alignment = align_center

            is_high_risk, reason = False, ""
            if url in nuclei_findings: is_high_risk, reason = True, f"🔥 [Nuclei 탐지] {' / '.join(list(set(nuclei_findings[url])))}"
            elif 'TruffleHog' in data["tools"]: is_high_risk, reason = True, "🔥 [Critical] TruffleHog: 기밀 키(Secret) 유출 검증됨"
            elif is_blacklist: is_high_risk, reason = True, "⚠️ [Warning] 파괴적 엔드포인트 수동 검점 요망"
            else:
                path_lower = urlparse(url).path.lower()
                if regex_infra_paths.search(path_lower): is_high_risk, reason = True, "🚨 [Infra] 인프라/버전관리 폴더 노출 의심"
                elif regex_sensitive_exts.search(path_lower): is_high_risk, reason = True, "🚨 [File] 민감한 파일 확장자 노출 (백업/설정)"
                elif regex_sensitive_paths.search(path_lower): is_high_risk, reason = True, "🚨 [Path] 관리자/디버그 콘솔 접근 의심"
                elif regex_credential_params.search(urlparse(url).query): is_high_risk, reason = True, "🚨 [Param] 파라미터 내 평문 인증 토큰 포착"

            if is_high_risk:
                high_risk_records.append({
                    "is_new_mark": is_new_mark,
                    "sub_mark": sub_mark,
                    "tools_str": tools_str,
                    "files_str": files_str,
                    "current_status": current_status,
                    "raw_target": raw_target,
                    "url": url,
                    "reason": reason,
                    "is_new": data.get("is_new", False),
                    "is_new_sub": is_new_subdomain,
                    "priority": get_status_priority(current_status)
                })

    high_risk_records.sort(key=lambda x: (not x["is_new"], x["priority"], x["raw_target"], x["url"]))
    high_risk_idx = 3
    
    for hr in high_risk_records:
        ws_high.append([high_risk_idx - 2, hr["is_new_mark"], hr["sub_mark"], escape_formula(hr["tools_str"]), escape_formula(hr["files_str"]), hr["current_status"], escape_formula(hr["raw_target"]), escape_formula(hr["url"]), escape_formula(hr["reason"])])
        for c in range(1, 10):
            cell = ws_high.cell(high_risk_idx, c)
            cell.font = font_data; cell.border = thin_border
            if (high_risk_idx % 2) == 1: cell.fill = fill_zebra
            if c == 2 and hr["is_new"]: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            if c == 3 and hr["is_new_sub"]: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            if c == 6: cell.fill = PatternFill(start_color=get_status_color(hr["current_status"]), end_color=get_status_color(hr["current_status"]), fill_type='solid'); cell.font = Font(name='Malgun Gothic', bold=True, color='FFFFFF'); cell.alignment = align_center
            elif c in [4, 5, 7, 8, 9]: cell.alignment = align_left
            else: cell.alignment = align_center
        high_risk_idx += 1

    if all_today_discovered_urls:
        cursor.executemany("INSERT OR IGNORE INTO master_urls (url) VALUES (?)", [(u,) for u in list(set(all_today_discovered_urls))])
        today_subs = {urlparse(u).netloc.split(':')[0] for u in all_today_discovered_urls if urlparse(u).netloc}
        if today_subs:
            cursor.executemany("INSERT OR IGNORE INTO historical_subdomains (subdomain) VALUES (?)", [(s,) for s in today_subs])
        conn.commit()
    conn.close()

    # 💡 [핵심 패치 4] 엑셀 수식이 아닌 파이썬 변수로 계산하여 텍스트 깨짐 방어
    if dash_idx > 2:
        ws_dash.append([
            "", "📊 총 합계 (Total)", "-", 
            f"{g_passive_tot} / {g_passive_new}", 
            f"{g_jsluice_tot} / {g_jsluice_new}", 
            f"{g_katana_tot} / {g_katana_new}", 
            g_nuc, g_truf, g_200, g_40x, g_50x
        ])
        for c in range(1, len(dash_headers) + 1):
            cell = ws_dash.cell(dash_idx, c)
            cell.font = Font(name='Malgun Gothic', size=11, bold=True, color='FFFFFF'); cell.fill = PatternFill(start_color='1F4E78', end_color='1F4E78', fill_type='solid')
            cell.border = thin_border; cell.alignment = align_center if c != 2 else align_left

    for sheet in wb.worksheets:
        header_row = 1 if sheet.title == "Summary Dashboard" else 2
        for col_idx, col in enumerate(sheet.columns, 1):
            col_letter = get_column_letter(col_idx)
            header = str(sheet.cell(header_row, col_idx).value or "")
            if header in ["타겟 절대 경로 (URL)", "고위험 경로 (Endpoint)"]: sheet.column_dimensions[col_letter].width = 80  
            elif header == "발견된 JS 파일명": sheet.column_dimensions[col_letter].width = 50  
            elif header in ["탐지 사유", "Gemini AI 지능형 헌팅 가이드 심층 분석"]: sheet.column_dimensions[col_letter].width = 55  
            elif header in ["📊 누적 / 🔥 신규 URL", "jsluice (누적 / 신규)", "Katana (누적 / 신규)"]: sheet.column_dimensions[col_letter].width = 24
            elif header in ["응답 상태", "🔥 신규여부", "🔥 신규 발견", "🌟 신규 서브", "🔮 취약점 발생 확률"]: sheet.column_dimensions[col_letter].width = 16
            else: sheet.column_dimensions[col_letter].width = 18

    ws_dash.column_dimensions['B'].width = 35
    if "🔮 Gemini AI Ranking" in wb.sheetnames: wb["🔮 Gemini AI Ranking"].column_dimensions['D'].width = 80
    
    wb.save(f'reports/passive_recon_report_{now_str}.xlsx')
    
    with open(f'reports/postman_collection_{now_str}.json', 'w', encoding='utf-8') as f:
        json.dump(postman_collection, f, indent=4, ensure_ascii=False)
        
    print(f"[+] Postman/Burp Suite 연동 명세서 사출 완료!", flush=True)

if __name__ == '__main__':
    build_advanced_excel_report()
