#!/usr/bin/env python3
import os
import glob
import requests

def get_secure_link(file_path, file_name):
    """
    깃허브 공용 IP 차단을 뚫기 위한 3중 보안 링크 발전소 (Failover Chain)
    """
    # --- 1차 시도: file.io ---
    print("[+] Attempting Provider 1: file.io ...")
    try:
        with open(file_path, 'rb') as f:
            res = requests.post('https://file.io', files={'file': f}, timeout=15)
        # 200 OK이면서 내부 내용이 JSON 규격이 맞는지 안전하게 검사
        if res.status_code == 200 and res.text.strip().startswith('{'):
            data = res.json()
            if data.get('success'):
                return data.get('link'), "1회 다운로드 완료 시 즉시 폭파"
        print("[-] Provider 1 (file.io) is blocked or rate-limited by Cloudflare. Tossing to Provider 2...")
    except Exception as e:
        print(f"[-] Provider 1 Error: {e}")

    # --- 2차 시도: transfer.sh (텍스트 반환 방식이라 차단에 매우 강함) ---
    print("[+] Attempting Provider 2: transfer.sh ...")
    try:
        with open(file_path, 'rb') as f:
            res = requests.put(f'https://transfer.sh/{file_name}', data=f, timeout=20)
        if res.status_code == 200 and res.text.strip().startswith('http'):
            return res.text.strip(), "보관 기한 14일 (무제한 다운로드)"
        print("[-] Provider 2 (transfer.sh) failed. Tossing to Provider 3...")
    except Exception as e:
        print(f"[-] Provider 2 Error: {e}")

    # --- 3차 시도: 0x0.st (개발자 전용 초경량 인프라) ---
    print("[+] Attempting Provider 3: 0x0.st ...")
    try:
        with open(file_path, 'rb') as f:
            res = requests.post('https://0x0.st', files={'file': f}, timeout=20)
        if res.status_code == 200 and res.text.strip().startswith('http'):
            return res.text.strip(), "보관 기한 30일 (무제한 다운로드)"
    except Exception as e:
        print(f"[-] Provider 3 Error: {e}")

    return None, None

def upload_report_via_secure_link():
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
    if not webhook_url:
        print("[-] Error: DISCORD_WEBHOOK_URL environment variable is missing.")
        return

    # reports/ 폴더 내에서 생성된 엑셀 마스터 보고서 목록 탐색
    files = glob.glob('reports/passive_recon_report_v*.xlsx')
    if not files:
        print("[-] Error: No excel report found in reports/ folder.")
        return
    
    latest_file = max(files, key=os.path.getmtime)
    file_name = os.path.basename(latest_file)
    file_size = os.path.getsize(latest_file)

    print(f"[+] Found latest report: {file_name} ({file_size / 1024 / 1024:.2f} MB)")
    
    # 3중 우회 엔진 가동하여 안전 링크 확보
    secure_link, security_policy = get_secure_link(latest_file, file_name)
    
    if not secure_link:
        print("[-] [CRITICAL] All 3 link providers failed due to GitHub Actions IP Ban.")
        return

    # 디스코드 전송 템플릿 빌드
    discord_message = (
        f"🚀 **[정찰 완료 - 대용량 마스터 보고서]**\n"
        f"📊 파일명: `{file_name}`\n"
        f"⚖️ 파일 크기: `{file_size / 1024 / 1024:.2f} MB`\n\n"
        f"🔒 **보안 다운로드 링크:**\n"
        f"🔗 {secure_link}\n\n"
        f"💡 *보안 정책: {security_policy}*"
    )
    
    print(f"[+] Transmitting secure link to Private Discord Channel...")
    response = requests.post(webhook_url, json={'content': discord_message})

    if response.status_code in [200, 204]:
        print("[+] [SUCCESS] Secure link transmitted to Discord successfully!")
    else:
        print(f"[-] Error sending to Discord: Status {response.status_code}, {response.text}")

if __name__ == '__main__':
    upload_report_via_secure_link()
