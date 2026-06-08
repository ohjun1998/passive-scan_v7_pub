#!/usr/bin/env python3
import os
import glob
import re
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def build_advanced_excel_report():
    print("[+] Initializing Modern Premium Excel Dashboard Engine...", flush=True)
    if not os.path.exists('targets.txt'):
        print("[-] Error: targets.txt missing.", flush=True)
        return
    with open('targets.txt', 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    # 다차원 데이터 매트릭스 선언
    matrix_data = {domain: {} for domain in targets}
    txt_files = glob.glob('results/**/*.*', recursive=True) + glob.glob('results/*.*')
    txt_files = [f for f in txt_files if os.path.isfile(f)]

    if not txt_files:
        print("[-] Warning: No decrypted text files found in results/ folder. Generating empty dashboard entries.", flush=True)

    # 1. 원천 데이터 파싱 및 매트릭스 구성
    for file_path in txt_files:
        filename = os.path.basename(file_path).lower()
        if 'linkfinder' in filename or 'jsluice' in filename: source_tool = 'LinkFinder'
        elif 'trufflehog' in filename: source_tool = 'TruffleHog'
        elif 'waybackurls' in filename: source_tool = 'Waybackurls'
        elif 'gau' in filename: source_tool = 'GAU'
        else: continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str.startswith('#'): continue
                    
                    # openpyxl IllegalCharacterError 방지를 위한 XML 제어 문자 제거
                    line_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', line_str)
                    if not line_str: continue
                    
                    # 탭(\t) 구분자가 존재할 경우 원본 실물 파일명 분리 추출
                    js_file = "Passive Archive"
                    if '\t' in line_str:
                        parts = line_str.split('\t', 1)
                        js_file = parts[0]
                        url = parts[1]
                    else:
                        url = line_str
                    
                    for domain in targets:
                        if domain in url or domain in filename:
                            if url not in matrix_data[domain]:
                                matrix_data[domain][url] = {"tools": set(), "files": set()}
                            matrix_data[domain][url]["tools"].add(source_tool)
                            if source_tool in ['LinkFinder', 'TruffleHog']:
                                matrix_data[domain][url]["files"].add(js_file)
                            break
        except Exception as e:
            print(f"[-] Error reading {filename}: {e}", flush=True)

    # 2. 엑셀 워크북 생성 및 스타일 정의
    wb = Workbook()
    
    font_header = Font(name='Malgun Gothic', size=11, bold=True, color='FFFFFF')
    fill_header = PatternFill(start_color='2F3542', end_color='2F3542', fill_type='solid') 
    fill_zebra = PatternFill(start_color='F8F9FA', end_color='F8F9FA', fill_type='solid')  
    fill_summary = PatternFill(start_color='E9ECEF', end_color='E9ECEF', fill_type='solid') 
    
    font_data = Font(name='Malgun Gothic', size=10, color='333333')
    font_summary = Font(name='Malgun Gothic', size=11, bold=True, color='000000')
    
    align_center = Alignment(horizontal='center', vertical='center')
    align_left = Alignment(horizontal='left', vertical='center')
    align_right = Alignment(horizontal='right', vertical='center')
    
    thin_side = Side(border_style="thin", color="E0E0E0")
    thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
    double_bottom_side = Side(border_style="double", color="2F3542")
    summary_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=double_bottom_side)

    # ==========================================
    # 3. Summary Dashboard 시트 설계
    # ==========================================
    ws_dash = wb.active
    ws_dash.title = "Summary Dashboard"
    
    dash_headers = ["No", "Target Domain", "Total URLs (Wayback/GAU)", "jsluice 추출 개수", "TruffleHog 탐지 개수"]
    ws_dash.append(dash_headers)
    ws_dash.row_dimensions[1].height = 28
    
    for col_num, header in enumerate(dash_headers, 1):
        cell = ws_dash.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center
        cell.border = thin_border

    # ==========================================
    # 4. High Risk Targets 시트 설계
    # ==========================================
    ws_high = wb.create_sheet(title="High Risk Targets")
    high_headers = ["No", "Source Tool", "Found in JS File", "Domain", "High Risk URL / Endpoint", "Risk Reason"] 
    ws_high.append(high_headers)
    ws_high.row_dimensions[1].height = 28
    
    for col_num, header in enumerate(high_headers, 1):
        cell = ws_high.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center
        cell.border = thin_border

    high_risk_keywords = ['config', '.env', 'xml', 'json', 'secret', 'api/v', 'token', 'admin', 'password', 'key', 'credential', 'mysql']
    dash_idx = high_risk_idx = 2  
    sheets_created = 0

    # 데이터 채우기 루프
    for domain, url_map in matrix_data.items():
        if not url_map:
            passive_url_count = 0
            jsluice_count = 0
            trufflehog_count = 0
        else:
            passive_url_count = sum(1 for url, data in url_map.items() if 'Waybackurls' in data["tools"] or 'GAU' in data["tools"])
            jsluice_count = sum(1 for url, data in url_map.items() if 'LinkFinder' in data["tools"])
            trufflehog_count = sum(1 for url, data in url_map.items() if 'TruffleHog' in data["tools"])
        
        # 대시보드 행 삽입
        ws_dash.append([dash_idx - 1, domain, passive_url_count, jsluice_count, trufflehog_count])
        ws_dash.row_dimensions[dash_idx].height = 22
        
        for col_num in range(1, 6):
            cell = ws_dash.cell(row=dash_idx, column=col_num)
            cell.font = font_data
            cell.border = thin_border
            if (dash_idx % 2) == 1: cell.fill = fill_zebra
            
            if col_num in [1, 2]:
                cell.alignment = align_center if col_num == 1 else align_left
                if col_num == 2 and url_map:
                    cell.hyperlink = f"#'{domain[:30]}'!A1"
                    cell.font = Font(name='Malgun Gothic', size=10, color='0056B3', underline='single')
            else:
                cell.alignment = align_right
                cell.number_format = '#,##0'
                
        dash_idx += 1

        if not url_map: continue

        # 개별 도메인 탭 추가
        ws = wb.create_sheet(title=domain[:30])
        sheets_created += 1
        ws.append(["No", "Source Tool", "Found in JS File", "Target URL / Endpoint"]) 
        ws.row_dimensions[1].height = 28
        for col_num in range(1, 5):
            cell = ws.cell(row=1, column=col_num)
            cell.font = font_header
            cell.fill = fill_header
            cell.alignment = align_center
            cell.border = thin_border

        for sub_idx, (url, data) in enumerate(sorted(url_map.items()), 1):
            if sub_idx > 1048500: break
            tools_str = ", ".join(sorted(list(data["tools"])))
            files_str = ", ".join(sorted(list(data["files"]))) if data["files"] else "-"
            ws.append([sub_idx, tools_str, files_str, url]) 
            
            row_num = sub_idx + 1
            ws.row_dimensions[row_num].height = 20
            for c in range(1, 5):
                cell = ws.cell(row=row_num, column=c)
                cell.font = font_data
                cell.border = thin_border
                if (row_num % 2) == 1: cell.fill = fill_zebra
                cell.alignment = align_center if c != 4 else align_left 

            # 하이 리스크 필터링 가동
            is_high_risk = False
            reason = ""
            if 'TruffleHog' in data["tools"]:
                is_high_risk = True
                reason = "TruffleHog 검증 완료 핵심 민감 키(Secret) 유출 징후"
            else:
                matched_keys = [key for key in high_risk_keywords if key in url.lower()]
                if matched_keys:
                    is_high_risk = True
                    reason = f"민감 키워드 파라미터 감지 ({', '.join(matched_keys)})"
                    
            if is_high_risk:
                ws_high.append([high_risk_idx - 1, tools_str, files_str, domain, url, reason]) 
                ws_high.row_dimensions[high_risk_idx].height = 22
                for c in range(1, 7):
                    cell = ws_high.cell(row=high_risk_idx, column=c)
                    cell.font = font_data
                    cell.border = thin_border
                    if (high_risk_idx % 2) == 1: cell.fill = fill_zebra
                    cell.alignment = align_left if c in [4, 5, 6] else align_center 
                high_risk_idx += 1

    # ==========================================
    # 5. Dashboard 최하단 자동 Total(합계) 행 연산부
    # ==========================================
    if dash_idx > 2:
        ws_dash.append([
            "Total", 
            f"{dash_idx - 2} 개 도메인 스캔 완료", 
            f"=SUM(C2:C{dash_idx-1})", 
            f"=SUM(D2:D{dash_idx-1})", 
            f"=SUM(E2:E{dash_idx-1})"
        ])
        ws_dash.row_dimensions[dash_idx].height = 26
        for col_num in range(1, 6):
            cell = ws_dash.cell(row=dash_idx, column=col_num)
            cell.font = font_summary
            cell.fill = fill_summary
            cell.border = summary_border
            if col_num in [1, 2]:
                cell.alignment = align_center if col_num == 1 else align_left
            else:
                cell.alignment = align_right
                cell.number_format = '#,##0'

    # ==========================================
    # 6. 전 시트 자동 열 너비 맞춤 및 상한선 상한 제어 알고리즘
    # ==========================================
    for sheet in wb.worksheets:
        headers = [cell.value for cell in sheet[1]]
        
        for col_idx, col in enumerate(sheet.columns, 1):
            max_len = 0
            col_letter = get_column_letter(col_idx)
            header_value = headers[col_idx - 1] if col_idx <= len(headers) else None
            
            for cell in col:
                if cell.value:
                    val_str = str(cell.value)
                    if not val_str.startswith('='):
                        cell_len = sum(2 if ord(char) > 128 else 1 for char in val_str)
                        if cell_len > max_len: max_len = cell_len
            
            calculated_width = max(max_len + 4, 12)
            
            # [요구사항 반영] 너무 길어지던 핵심 텍스트 컬럼의 가로폭 제한 락(Lock) 다운 조정
            if header_value in ["High Risk URL / Endpoint", "Target URL / Endpoint"]:
                sheet.column_dimensions[col_letter].width = 45  # 60에서 45로 줄여 가로 스크롤 방지
            elif header_value == "Found in JS File":
                sheet.column_dimensions[col_letter].width = 20  # 30에서 20으로 조절하여 깔끔하게 세팅
            elif header_value == "Risk Reason":
                sheet.column_dimensions[col_letter].width = 40  
            else:
                sheet.column_dimensions[col_letter].width = calculated_width

    # 대시보드 고정폭 셋업
    ws_dash.column_dimensions['A'].width = 10
    ws_dash.column_dimensions['B'].width = 35
    ws_dash.column_dimensions['C'].width = 26
    ws_dash.column_dimensions['D'].width = 22
    ws_dash.column_dimensions['E'].width = 22

    os.makedirs('reports', exist_ok=True)
    wb.save('reports/passive_recon_report_v1.xlsx')
    print("[+] [SUCCESS] Premium Multi-Tab Excel Document Successfully Constructed.", flush=True)

if __name__ == '__main__':
    build_advanced_excel_report()
