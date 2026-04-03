import os
import ipaddress
import dns.resolver
from dotenv import load_dotenv
from fastapi import FastAPI
from urllib.parse import urlparse
from pydantic import BaseModel
import whois
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import traceback

# 載入 .env 檔案
load_dotenv()

# 讀取 API
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
BREACH_API_KEY = os.getenv("BREACH_API_KEY", "")

app = FastAPI(title="CyberGuard")

# 定義資料格式
class URLRequest(BaseModel):
    url: str

class ContentRequest(BaseModel):
    content: str

# API 重試機制
session = requests.Session()
retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))


# --- 網址與 IP 掃描 ---
@app.post("/api/scan_url")
def scan_url(request: URLRequest):
    raw_url = request.url.strip()
    
    # 確保網址有 http
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    # 截出網域或 IP
    target = urlparse(raw_url).hostname

    if not target:
        return {"status": "錯誤", "message": "❌ 無效的網址格式"}

    report_details = []
    danger_score = 0
    ip_addr = "無法解析"
    is_ip = False

    # 判斷輸入（IP 或網域）
    try:
        ipaddress.ip_address(target)
        is_ip = True
        ip_addr = target  
    except ValueError:
        is_ip = False

    # DNS 解析
    if not is_ip: # 只查網域
        resolved = False
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0 # 防卡死
        
        # 查 IPv4
        try:
            answers = resolver.resolve(target, 'A')
            ip_addr = answers[0].to_text()
            resolved = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        
        # 查 IPv6
        if not resolved:
            try:
                answers = resolver.resolve(target, 'AAAA')
                ip_addr = answers[0].to_text()
                report_details.append(f"ℹ️ 偵測到 IPv6: `{ip_addr}`")
                resolved = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
                
        # 嘗試補上 www.
        if not resolved and not target.startswith("www."):
            target_with_www = f"www.{target}"
            try:
                answers = resolver.resolve(target_with_www, 'A')
                ip_addr = answers[0].to_text()
                report_details.append(f"🔄 自動追蹤子網域: `{target_with_www}`")
                target = target_with_www 
                resolved = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
                
        if not resolved:
            report_details.append("⚠️ IP 解析失敗 (可能無效或無伺服器紀錄)")

    # 查詢 AbuseIPDB
    if ip_addr != "無法解析" and ABUSEIPDB_API_KEY and "你的" not in ABUSEIPDB_API_KEY:
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            abuse_headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
            abuse_params = {"ipAddress": ip_addr, "maxAgeInDays": "90"}
            
            abuse_res = session.get(abuse_url, headers=abuse_headers, params=abuse_params, timeout=5)

            if abuse_res.status_code == 200:
                ip_score = abuse_res.json()['data']['abuseConfidenceScore']
                report_details.append(f"🔍 惡意風險指數: `{ip_score}％`")
                
                # IP 風險分級
                if ip_score > 80:
                    danger_score += 70
                    report_details.append("🚩 AbuseIPDB 警告：此 IP 具備極高惡意風險")
                elif ip_score > 40:
                    danger_score += 40
                    report_details.append("⚠️ AbuseIPDB 警告：此 IP 有可疑舉報紀錄")
        except requests.exceptions.RequestException:
            report_details.append("⚠️ AbuseIPDB 檢查超時或連線失敗")

    # 4. 查網域年資
    if not is_ip:
        try:
            w = whois.whois(target)
            c_date = w.creation_date
            if isinstance(c_date, list): 
                c_date = c_date[0]

            if c_date:
                days = (datetime.now() - c_date.replace(tzinfo=None)).days
                report_details.append(f"📅 網域年資: `{days}` 天")
                
                if days < 30:
                    danger_score += 40
                    report_details.append("🚩 網域極新，可能是剛建立的釣魚站")
        except Exception as e: 
            # 捕捉錯誤類型
            report_details.append(f"⚠️ WHOIS 查詢失敗: {type(e).__name__}")

    # VirusTotal 掃描
    if VT_API_KEY and "你的" not in VT_API_KEY:
        try:
            # 動態切換查 IP 或 Domain
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if is_ip else f"https://www.virustotal.com/api/v3/domains/{target}"
            vt_headers = {"x-apikey": VT_API_KEY}
            vt_res = session.get(vt_url, headers=vt_headers, timeout=5)

            if vt_res.status_code == 200:
                vt_stats = vt_res.json()['data']['attributes']['last_analysis_stats']
                malicious = vt_stats.get('malicious', 0)
                
                if malicious > 0:
                    report_details.append(f"🚨 VT 警告：有 {malicious} 家資安廠商列為黑名單")
                    # VT 風險分級
                    if malicious >= 3:
                        danger_score += 100 
                    else:
                        danger_score += 60  
        except requests.exceptions.RequestException:
            report_details.append("⚠️ VT 引擎掃描逾時或連線失敗")

    # 結算並產生報告
    try:
        final_status = "✅ 安全"
        if danger_score >= 100: 
            final_status = "💀 極度危險"
        elif danger_score >= 50: 
            final_status = "⚠️ 高風險"

        formatted_details = "\n" + "\n".join([f"   {item}" for item in report_details])
        target_label = "📍 **目標 IP:**" if is_ip else "🌐 **網域:**"

        full_message = (
            f"🛡️ **【掃描報告】**\n\n"
            f"{target_label} `{target}`\n"
            f"📍 **解析 IP:** `{ip_addr}`\n"
            f"📊 **綜合判定:** **{final_status}** (風險值: {danger_score})\n\n"
            f"📝 **掃描詳情:** {formatted_details}"
        )
        return {"status": final_status, "message": full_message}
        
    except Exception as e:
        print(traceback.format_exc())
        return {"status": "錯誤", "message": f"❌ 報告生成失敗: {str(e)}"}


# --- 個資外洩偵測 ---
def identify_input(text: str) -> str:
    text = text.strip()
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", text):
        return "email"
    if re.match(r"^(\+886|886|0)9\d{8}$", text):
        return "phone"
    return "unknown"

@app.post("/api/check_leak")
def check_leak(request: ContentRequest):
    raw_input = request.content.strip()
    input_type = identify_input(raw_input)
    search_term = raw_input

    if input_type == "phone":
        search_term = search_term.replace("+", "").replace("-", "").replace(" ", "")
        if search_term.startswith("09"):
            search_term = "886" + search_term[1:]
    elif input_type == "unknown":
        return {"status": "錯誤", "message": "❌ 格式不支援！請輸入正確的 Email 或手機號碼 (09...)"}

    headers = {
        "x-rapidapi-key": BREACH_API_KEY,
        "x-rapidapi-host": "breachdirectory.p.rapidapi.com"
    }

    try:
        res = session.get(
            "https://breachdirectory.p.rapidapi.com/passwords", 
            headers=headers, 
            params={"func": "auto", "term": search_term},
            timeout=8
        )
        data = res.json()
        found = data.get("found", 0)

        if found > 0:
            return {
                "status": "危險", 
                "message": f"🚨 **個資外洩警報！**\n這組 {input_type} (`{raw_input}`) 曾在 **{found}** 處外洩資料庫中出現過！建議立即檢查並更改密碼。"
            }
        return {"status": "安全", "message": f"✅ **掃描完成**\n這組 {input_type} (`{raw_input}`) 目前查無公開外洩紀錄。"}

    except requests.exceptions.RequestException:
        return {"status": "錯誤", "message": "❌ 無法連接外洩資料庫，請稍後再試。"}