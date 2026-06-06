#!/usr/bin/env python3
import os
import glob
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def upload_latest_report():
    SCOPES = ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/drive']
    SERVICE_ACCOUNT_FILE = 'service_account.json'
    FOLDER_ID = os.environ.get('GDRIVE_FOLDER_ID')

    if not FOLDER_ID:
        print("[-] Error: GDRIVE_FOLDER_ID environment variable is missing.")
        return

    # reports/ 폴더 내에서 생성된 엑셀 마스터 보고서 목록 탐색
    files = glob.glob('reports/passive_recon_report_v*.xlsx')
    if not files:
        print("[-] Error: No excel report found in reports/ folder.")
        return
    
    # 가장 최근에 수정/생성된 최신 버전 파일 선택
    latest_file = max(files, key=os.path.getmtime)
    file_name = os.path.basename(latest_file)

    print(f"[+] Authenticating Service Account to Google Drive API...")
    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    service = build('drive', 'v3', credentials=creds)

    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID]
    }
    
    # [★용량 초과 에러 해결★] 
    # resumable=False로 지정하여 구글 서버가 로봇 계정 자체의 0MB 기본 용량을 선행 검사하는 정문을 우회합니다.
    media = MediaFileUpload(latest_file, 
                            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                            resumable=False)

    print(f"[+] Uploading {file_name} to Google Drive Safe Folder (ID: {FOLDER_ID})...")
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"[+] [SUCCESS] File transmission complete! Drive File ID: {file.get('id')}")

if __name__ == '__main__':
    upload_latest_report()
