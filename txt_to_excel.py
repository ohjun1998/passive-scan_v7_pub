#!/usr/bin/env python3
import os
import glob
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

def build_advanced_excel_report():
    print("[+] Initializing Optimized Multi-Tab Excel Engine...", flush=True)
    
    if not os.path.exists('targets.txt'):
        print("[-] Error: targets.txt missing.", flush=True)
        return
        
    with open('targets.txt', 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    matrix_data = {domain: {} for domain in targets}

    # 16대 가상머신 데이터 전수조사
    txt_files = glob.glob('results/**/*.*', recursive=True) + glob.glob('results/*.*')
    txt_files = [f for f in txt_files if os.path.isfile(f)]

    if not txt_files:
        print("[-] Warning: No decrypted text files found in results/ folder.", flush=True)
        return

    print(f"[+] Processing {len(txt_files)} data source files...", flush=True)
    
    for file_path in txt_files:
        filename = os.path.basename(file_path).lower()
        if 'linkfinder' in filename: source_tool = 'LinkFinder'
        elif 'trufflehog' in filename: source_tool = 'TruffleHog'
        elif 'waybackurls' in filename: source_tool = 'Waybackurls'
        elif 'gau' in filename: source_tool = 'GAU'
        else: source_tool = 'Combined-Engine'

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    url = line.strip()
                    if not url or url.startswith('#'): continue
                    
                    for domain in targets:
                        if domain in url or domain in filename:
                            if url not in matrix_data[domain]:
                                matrix_data[domain][url] = set()
                            matrix_data[domain][url].add(source_tool)
                            break
        except Exception as e:
            print(f"[-] Error reading {filename}: {e}", flush=True)

    print("[+] Compiling Master Excel Workbook with Tabs...", flush=True)
    wb = Workbook()

    font_header = Font(name='Malgun Gothic', size=11, bold=True, color='FFFFFF')
    fill_header = PatternFill(start_color='1F4E78', end_color='1F4E78', fill_type='solid')
    align_center = Alignment(horizontal='center', vertical='center')

    # Dashboard 시트 세팅
    ws_dash = wb.active
    ws_dash.title = "Dashboard"
    dash_headers = ["No", "Target Domain (대상 도메인)", "Total URLs (총 URL 합계)", "Verified Secrets (TruffleHog 검증 건수)"]
    ws_dash.append(dash_headers)
    ws_dash.row_dimensions[1].height = 26
    for col_num in range(1, 5):
        cell = ws_dash.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center

    # High Risk Targets 시트 세팅
    ws_high = wb.create_sheet(title="High Risk Targets")
    high_headers = ["No", "Domain (도메인)", "High Risk URL / Endpoint (위험 주소)", "Source Tool (탐지 도구)", "Risk Reason (위험 사유)"]
    ws_high.append(high_headers)
    ws_high.row_dimensions[1].height = 26
    for col_num in range(1, 6):
        cell = ws_high.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center

    high_risk_keywords = ['config', '.env', 'xml', 'json', 'secret', 'api/v', 'token', 'admin', 'password', 'key', 'credential', 'mysql']
    
    dash_idx = 1
    high_risk_idx = 1
    sheets_created = 0

    for domain, url_map in matrix_data.items():
        if not url_map: continue
        
        total_urls = len(url_map)
        # 이제 가장 중요한 TruffleHog 핵심 자격증명 탐지 건수만 대시보드 위험 지표로 누적합니다.
        verified_secrets_count = sum(1 for url, tools in url_map.items() if 'TruffleHog' in tools)
        ws_dash.append([dash_idx, domain, total_urls, verified_secrets_count])
        dash_idx += 1

        safe_tab_name = domain[:30]
        ws = wb.create_sheet(title=safe_tab_name)
        sheets_created += 1

        headers = ["No", "Target URL / Endpoint (수집된 자산 주소)", "Source Tool (발견 도구)"]
        ws.append(headers)
        ws.row_dimensions[1].height = 26
        for col_num in range(1, 4):
            cell = ws.cell(row=1, column=col_num)
            cell.font = font_header
            cell.fill = fill_header
            cell.alignment = align_center

        sorted_dataset = sorted(url_map.items(), key=lambda x: x[0])
        for idx, (url, tools) in enumerate(sorted_dataset, 1):
            if idx > 1048500: break
            tools_str = ", ".join(sorted(list(tools)))
            ws.append([idx, url, tools_str])

            is_high_risk = False
            reason = ""
            # TruffleHog가 찾은 자산이 1순위 High Risk 자산이 됩니다.
            if 'TruffleHog' in tools:
                is_high_risk = True
                reason = "TruffleHog 실시간 유효성 검증 완료된 핵심 API Key 유출"
            else:
                # LinkFinder나 타 도구가 찾은 경로 중 민감 키워드가 섞인 엔드포인트를 2순위 정밀 분류합니다.
                url_lower = url.lower()
                matched_keys = [key for key in high_risk_keywords if key in url_lower]
                if matched_keys:
                    is_high_risk = True
                    reason = f"민감 엔드포인트 노출 파라미터 감지 ({', '.join(matched_keys)})"
                    
            if is_high_risk:
                ws_high.append([high_risk_idx, domain, url, tools_str, reason])
                high_risk_idx += 1

        ws.column_dimensions['A'].width = 8
        ws.column_dimensions['B'].width = 85
        ws.column_dimensions['C'].width = 18

    ws_dash.column_dimensions['A'].width = 8
    ws_dash.column_dimensions['B'].width = 35
    ws_dash.column_dimensions['C'].width = 25
    ws_dash.column_dimensions['D'].width = 25

    ws_high.column_dimensions['A'].width = 8
    ws_high.column_dimensions['B'].width = 25
    ws_high.column_dimensions['C'].width = 85
    ws_high.column_dimensions['D'].width = 15
    ws_high.column_dimensions['E'].width = 35

    if sheets_created > 0:
        os.makedirs('reports', exist_ok=True)
        report_path = 'reports/passive_recon_report_v1.xlsx'
        wb.save(report_path)
        print(f"[+] [SUCCESS] Clean Master Tabbed Excel Report created at: {report_path}", flush=True)
    else:
        print("[-] Error: Scan results were empty. Excel file not created.", flush=True)

if __name__ == '__main__':
    build_advanced_excel_report()
