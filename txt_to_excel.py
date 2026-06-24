#!/usr/bin/env python3
import os
import glob
import re
import json
import posixpath
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

def build_advanced_excel_report():
    print("[+] 초고속 텍스트 DB 기반 차분 분석(Differential Analysis) 엔진 가동 중...", flush=True)
    if not os.path.exists('targets.txt'): return
    with open('targets.txt', 'r') as f: targets = [line.strip() for line in f if line.strip()]

    target_map = {get_safe_domain(t): t for t in targets}
    
    downloaded_js_set = set()
    prev_js_db_path = 'previous_report/downloaded_js_db.txt'
    if os.path.exists(prev_js_db_path):
        try:
            with open(prev_js_db_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url: downloaded_js_set.add(url)
            print(f"[*] JS 분석 이력 DB 로드 완료 (총 {len(downloaded_js_set)}개 스킵 예정)")
        except Exception as e:
            pass

    js_url_converter = {}
    for mf in glob.glob('results/*_js_mapping.txt'):
        try:
            with open(mf, 'r', errors='ignore') as f:
                for line in f:
                    if '\t' in line:
                        s, o = line.strip().split('\t', 1)
                        js_url_converter[s] = o
                        downloaded_js_set.add(o)
        except: pass

    previous_urls = set()
    prev_db_path = 'previous_report/master_url_db.txt'
    
    if os.path.exists(prev_db_path):
        try:
            print(f"[*] 이전 스캔 텍스트 DB({prev_db_path})를 불러옵니다...")
            with open(prev_db_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url: previous_urls.add(url)
            print(f"[+] 텍스트 DB 학습 완료 (과거 데이터베이스: {len(previous_urls)}개 엔드포인트 유지 중)")
        except Exception as e:
            print(f"[-] 텍스트 DB 파싱 실패 (모두 신규로 처리): {e}")
    else:
        print("[!] 이전 텍스트 DB가 없습니다. (최초 실행 - 모든 URL이 '신규'로 처리됩니다)")

    previous_subdomains = set()
    for u in previous_urls:
        try:
            previous_subdomains.add(urlparse(u).netloc)
        except: pass

    matrix_data = {raw_target: {} for raw_target in targets}
    signature_counts = {}
    
    junk_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.eot', '.ttf', '.mp4')
    blacklist_words = ['logout', 'signout', 'delete', 'remove', 'revoke', 'destroy']
    
    for file_path in glob.glob('results/*.*'):
        filename = os.path.basename(file_path).lower()
        match = re.match(r'^(.*)_(linkfinder|trufflehog|gau|waybackurls)\.txt$', filename)
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
                        if not (parsed_netloc == base_domain or parsed_netloc.endswith('.' + base_domain)):
                            continue
                    else:
                        if parsed_netloc != base_domain:
                            continue

                    if urlparse(abs_url).path.lower().endswith(junk_extensions): continue

                    parsed_for_sig = urlparse(abs_url)
                    query_keys = tuple(sorted([k for k, v in parse_qsl(parsed_for_sig.query, keep_blank_values=True)]))
                    norm_path = normalize_dynamic_path(parsed_for_sig.path)
                    path_dir = posixpath.dirname(norm_path)
                    path_ext = posixpath.splitext(norm_path)[1]
                    signature = (parsed_for_sig.netloc, path_dir, path_ext, query_keys)

                    if abs_url not in matrix_data[raw_target]:
                        if signature_counts.get(signature, 0) >= 5:
                            continue 
                        signature_counts[signature] = signature_counts.get(signature, 0) + 1
                        
                        is_new = abs_url not in previous_urls
                        matrix_data[raw_target][abs_url] = {"tools": set(), "files": set(), "is_new": is_new}
                        
                    matrix_data[raw_target][abs_url]["tools"].add(source_tool)
                    if source_tool in ['LinkFinder', 'TruffleHog']:
                        matrix_data[raw_target][abs_url]["files"].add(js_file)
        except: pass

    for prev_url in previous_urls:
        parsed_netloc = urlparse(prev_url).netloc.split(':')[0]
        matched_raw_target = None
        
        for raw_target in target_map.values():
            is_wildcard = raw_target.startswith('*.')
            base_domain = raw_target[2:] if is_wildcard else raw_target
            
            if is_wildcard:
                if parsed_netloc == base_domain or parsed_netloc.endswith('.' + base_domain):
                    matched_raw_target = raw_target
                    break
            else:
                if parsed_netloc == base_domain:
                    matched_raw_target = raw_target
                    break
                    
        if matched_raw_target:
            if prev_url not in matrix_data[matched_raw_target]:
                matrix_data[matched_raw_target][prev_url] = {
                    "tools": {"Passive Archive"},
                    "files": set(),
                    "is_new": False
                }

    os.makedirs('reports', exist_ok=True)

    all_cumulative_urls = set(previous_urls) 
    for url_map in matrix_data.values():
        for url in url_map.keys():
            all_cumulative_urls.add(url)     
            
    with open('reports/master_url_db.txt', 'w', encoding='utf-8') as f:
        for u in sorted(all_cumulative_urls):
            f.write(u + '\n')
    print(f"[+] 텍스트 DB 영구 누적 백업 완료 (총 {len(all_cumulative_urls)}개 기록됨)")

    with open('reports/downloaded_js_db.txt', 'w', encoding='utf-8') as f:
        for u in sorted(downloaded_js_set):
            f.write(u + '\n')

    total_new_found = sum(1 for url_map in matrix_data.values() for data in url_map.values() if data.get("is_new", False))
    with open('reports/new_count.txt', 'w') as f:
        f.write(str(total_new_found))

    # 💡 [핵심 패치] Httpx 및 Nuclei 결과 동시 파싱
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
                    name = data.get('info', {}).get('name', 'Unknown')
                    sev = data.get('info', {}).get('severity', 'INFO').upper()
                    if url:
                        if url not in nuclei_findings:
                            nuclei_findings[url] = []
                        nuclei_findings[url].append(f"[{sev}] {name}")
        except: pass

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

    # 💡 [핵심 패치] 대시보드 헤더에 '🔥 Nuclei 탐지' 추가
    ws_dash = wb.active
    ws_dash.title = "Summary Dashboard"
    dash_headers = [
        "No", "타겟 도메인", "🌟 신규 서브", "엑셀 누적 URL", "🔥 신규 발견", 
        "jsluice (기존)", "🔥 jsluice (신규)", "🔥 Nuclei 탐지", "TruffleHog 탐지", 
        "🟢 200 (OK)", "🟠 403/401 (권한)", "🔴 500대 (에러)"
    ]
    ws_dash.append(dash_headers)
    for c in range(1, len(dash_headers) + 1): 
        ws_dash.cell(1, c).font = font_header; ws_dash.cell(1, c).fill = fill_header
        ws_dash.cell(1, c).alignment = align_center; ws_dash.cell(1, c).border = thin_border

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

    dash_idx, high_risk_idx = 2, 3

    for raw_target, url_map in matrix_data.items():
        if not url_map: continue
        
        sheet_title = re.sub(r'[\\/\?\*\:\[\]]', '_', raw_target)[:30]
        
        postman_folder = {
            "name": raw_target,
            "item": []
        }

        passive_count = len(url_map)
        domain_new_count = sum(1 for data in url_map.values() if data.get("is_new", False))
        trufflehog_count = sum(1 for data in url_map.values() if 'TruffleHog' in data["tools"])
        jsluice_old = sum(1 for data in url_map.values() if 'LinkFinder' in data["tools"] and not data.get("is_new", False))
        jsluice_new = sum(1 for data in url_map.values() if 'LinkFinder' in data["tools"] and data.get("is_new", False))
        
        # 💡 [핵심 패치] 현재 타겟 도메인에서 발생한 Nuclei 탐지 건수 합산
        nuclei_count = sum(1 for u in url_map.keys() if u in nuclei_findings)
        
        count_200 = 0
        count_40x = 0
        count_50x = 0
        
        for url in url_map.keys():
            status = str(status_codes.get(url, 'Dead'))
            if status.startswith('2'): count_200 += 1
            elif status in ['401', '403']: count_40x += 1
            elif status.startswith('5'): count_50x += 1

        current_subdomains = {urlparse(u).netloc for u in url_map.keys()}
        new_subdomains = current_subdomains - previous_subdomains
        has_new_sub = bool(new_subdomains) and bool(previous_subdomains)
        sub_dash_mark = "🌟 신규" if has_new_sub else "-"
        
        ws_dash.append([
            dash_idx - 1, escape_formula(raw_target), sub_dash_mark, 
            passive_count, domain_new_count, 
            jsluice_old, jsluice_new, nuclei_count, trufflehog_count,
            count_200, count_40x, count_50x
        ])
        
        for c in range(1, len(dash_headers) + 1):
            cell = ws_dash.cell(dash_idx, c)
            cell.font = font_data; cell.border = thin_border
            cell.alignment = align_left if c == 2 else align_center
            
            if c == 2 and url_map:
                cell.hyperlink = f"#'{sheet_title}'!A1"
                cell.font = Font(name='Malgun Gothic', color='0056B3', underline='single')
            
            if c == 3 and has_new_sub: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            if c == 7 and jsluice_new > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
            if c == 8 and nuclei_count > 0: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                
        dash_idx += 1

        ws = wb.create_sheet(title=sheet_title)
        ws.append(["🔙 대시보드로 돌아가기 (Return to Dashboard)"])
        ws.merge_cells('A1:G1')
        back_cell = ws.cell(row=1, column=1)
        back_cell.hyperlink = "#'Summary Dashboard'!A1"
        back_cell.font = Font(name='Malgun Gothic', size=11, bold=True, color='0056B3', underline='single')
        back_cell.fill = PatternFill(start_color='E9ECEF', end_color='E9ECEF', fill_type='solid')
        back_cell.alignment = align_left

        ws.append(["No", "🔥 신규여부", "🌟 신규 서브", "소스 출처", "발견된 JS 파일명", "응답 상태", "타겟 절대 경로 (URL)"]) 
        for c in range(1, 8): ws.cell(2, c).font = font_header; ws.cell(2, c).fill = fill_header; ws.cell(2, c).alignment = align_center; ws.cell(2, c).border = thin_border

        sorted_urls = sorted(url_map.items(), key=lambda x: (not x[1].get("is_new", False), x[0]))

        for sub_idx, (url, data) in enumerate(sorted_urls, 1):
            if sub_idx > 1048500: break
            tools_str = ", ".join(sorted(list(data["tools"])))
            files_str = ", ".join(sorted(list(data["files"]))) if data["files"] else "-"
            
            is_new_mark = "🆕 NEW" if data.get("is_new", False) else "-"
            is_blacklist = any(b in url.lower() for b in blacklist_words)
            
            if not is_blacklist:
                parsed_pm = urlparse(url)
                path_parts = [p for p in parsed_pm.path.split('/') if p]
                query_items = parse_qsl(parsed_pm.query, keep_blank_values=True)
                pm_query = [{"key": k, "value": v} for k, v in query_items]
                
                request_item = {
                    "name": parsed_pm.path if parsed_pm.path else "/",
                    "request": {
                        "method": "GET",
                        "header": [],
                        "url": {
                            "raw": url,
                            "protocol": parsed_pm.scheme,
                            "host": parsed_pm.netloc.split('.'),
                            "path": path_parts,
                            "query": pm_query
                        }
                    }
                }
                postman_folder["item"].append(request_item)

            if is_blacklist:
                current_status = "Skipped(위험)"
            elif urlparse(url).path.lower().endswith(junk_extensions):
                current_status = "Static(생략)"
            else:
                current_status = status_codes.get(url, 'Dead')
            
            parsed_url_obj = urlparse(url)
            netloc = parsed_url_obj.netloc
            path_lower = parsed_url_obj.path.lower()
            query_string = parsed_url_obj.query
            
            is_new_subdomain = (netloc in new_subdomains) and bool(previous_subdomains)
            sub_mark = "🌟 신규" if is_new_subdomain else "-"

            row_num = sub_idx + 2
            ws.append([sub_idx, is_new_mark, sub_mark, escape_formula(tools_str), escape_formula(files_str), current_status, escape_formula(url)]) 
            
            for c in range(1, 8):
                cell = ws.cell(row_num, c)
                cell.font = font_data; cell.border = thin_border
                if (row_num % 2) == 1: cell.fill = fill_zebra
                
                if c == 2 and data.get("is_new", False): cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                if c == 3 and is_new_subdomain: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')

                if c == 6:
                    cell.fill = PatternFill(start_color=get_status_color(current_status), end_color=get_status_color(current_status), fill_type='solid')
                    cell.font = Font(name='Malgun Gothic', bold=True, color='FFFFFF'); cell.alignment = align_center
                elif c in [4, 5, 7]: cell.alignment = align_left
                else: cell.alignment = align_center

            is_high_risk, reason = False, ""
            
            # 💡 [핵심 패치] Nuclei가 잡아낸 실제 기술 스택 및 취약 노출 여부를 High Risk에 꽂아 넣음!
            if url in nuclei_findings:
                is_high_risk = True
                n_reasons = " / ".join(list(set(nuclei_findings[url]))) # 중복 제거
                reason = f"🔥 [Nuclei 탐지] {n_reasons}"
            elif 'TruffleHog' in data["tools"]: 
                is_high_risk, reason = True, "🔥 [Critical] TruffleHog: 소스코드 내 기밀 키(Secret) 유출 검증됨"
            elif is_blacklist: 
                is_high_risk, reason = True, "⚠️ [Warning] 파괴적 엔드포인트 (스캔 스킵됨 - 수동 점검 요망)"
            else:
                if regex_infra_paths.search(path_lower): 
                    is_high_risk, reason = True, "🚨 [Infra] 버전관리 및 인프라 폴더 노출 의심 (.git, .aws 등)"
                elif regex_sensitive_exts.search(path_lower): 
                    is_high_risk, reason = True, "🚨 [File] 민감한 파일 확장자 노출 (백업, 설정, 로그, DB)"
                elif regex_sensitive_paths.search(path_lower): 
                    is_high_risk, reason = True, "🚨 [Path] 관리자 패널 또는 디버그 엔드포인트 의심"
                elif regex_credential_params.search(query_string): 
                    is_high_risk, reason = True, "🚨 [Param] URL 파라미터에 민감한 인증 토큰/키 평문 노출 의심"
                    
            if is_high_risk:
                ws_high.append([high_risk_idx - 2, is_new_mark, sub_mark, escape_formula(tools_str), escape_formula(files_str), current_status, escape_formula(raw_target), escape_formula(url), escape_formula(reason)]) 
                for c in range(1, 10):
                    cell = ws_high.cell(high_risk_idx, c)
                    cell.font = font_data; cell.border = thin_border
                    if (high_risk_idx % 2) == 1: cell.fill = fill_zebra
                    
                    if c == 2 and data.get("is_new", False): cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                    if c == 3 and is_new_subdomain: cell.font = Font(name='Malgun Gothic', bold=True, color='E83E8C')
                    
                    if c == 6:
                        cell.fill = PatternFill(start_color=get_status_color(current_status), end_color=get_status_color(current_status), fill_type='solid')
                        cell.font = Font(name='Malgun Gothic', bold=True, color='FFFFFF'); cell.alignment = align_center
                    elif c in [4, 5, 7, 8, 9]: cell.alignment = align_left
                    else: cell.alignment = align_center
                high_risk_idx += 1

        if postman_folder["item"]:
            postman_collection["item"].append(postman_folder)

    if dash_idx > 2:
        sum_formulas = [f"=SUM({get_column_letter(c)}2:{get_column_letter(c)}{dash_idx-1})" for c in range(4, len(dash_headers) + 1)]
        ws_dash.append(["", "📊 총 합계 (Total)", "-"] + sum_formulas)
        for c in range(1, len(dash_headers) + 1):
            cell = ws_dash.cell(dash_idx, c)
            cell.font = Font(name='Malgun Gothic', size=11, bold=True, color='FFFFFF')
            cell.fill = PatternFill(start_color='1F4E78', end_color='1F4E78', fill_type='solid')
            cell.border = thin_border
            cell.alignment = align_center if c != 2 else align_left

    for sheet in wb.worksheets:
        header_row = 1 if sheet.title == "Summary Dashboard" else 2
        for col_idx, col in enumerate(sheet.columns, 1):
            col_letter = get_column_letter(col_idx)
            header_cell_value = sheet.cell(header_row, col_idx).value
            header = str(header_cell_value) if header_cell_value else ""
            
            if header in ["타겟 절대 경로 (URL)", "고위험 경로 (Endpoint)"]: sheet.column_dimensions[col_letter].width = 80  
            elif header == "발견된 JS 파일명": sheet.column_dimensions[col_letter].width = 50  
            elif header == "탐지 사유": sheet.column_dimensions[col_letter].width = 45  
            elif header == "응답 상태": sheet.column_dimensions[col_letter].width = 16
            elif header in ["🔥 신규여부", "🔥 신규 발견", "🌟 신규 서브"]: sheet.column_dimensions[col_letter].width = 15
            elif any(k in header for k in ["jsluice", "Nuclei", "TruffleHog", "200", "403", "500"]): sheet.column_dimensions[col_letter].width = 18
            else: sheet.column_dimensions[col_letter].width = 18

    ws_dash.column_dimensions['B'].width = 35
    wb.active = 0 
    
    report_filename = f"passive_recon_report_{now_str}.xlsx"
    wb.save(f'reports/{report_filename}')
    print(f"[+] 텍스트 DB 기반 누적 보고서({report_filename}) 렌더링 완료!")

    postman_filename = f"postman_collection_{now_str}.json"
    with open(f'reports/{postman_filename}', 'w', encoding='utf-8') as f:
        json.dump(postman_collection, f, indent=4, ensure_ascii=False)
    print(f"[+] Postman/Burp Suite 연동 API 명세서({postman_filename}) 사출 완료!", flush=True)

if __name__ == '__main__':
    build_advanced_excel_report()
