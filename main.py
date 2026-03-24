from fastapi import FastAPI
from pydantic import BaseModel
import whois
from datetime import datetime
import requests
import socket
import re
import traceback


# API 初始化

VT_API_KEY = ""

ABUSEIPDB_API_KEY = ""

BREACH_API_KEY = ""


app = FastAPI(title="CyberGuard Pro Ultimate API")

class URLRequest(BaseModel):
    url: str

class ContentRequest(BaseModel):
    content: str

# 偵測輸入類型
def identify_input(text):
    text = text.strip()
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", text):
        return "email"
    if re.match(r"^(\+886|886|0)9\d{8}$", text):
        return "phone"
    return "unknown"


# 功能一：網址、IP、AbuseIPDB、VT 綜合嚴謹掃描
@app.post("/api/scan_url")
def scan_url(request: URLRequest):
    # 提取網域
    raw_url = request.url.strip()
    domain = raw_url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].split(":")[0]
    
    report_details = []
    danger_score = 0
    ip_addr = "無法解析"

    try:
        # IP 溯源與行為檢查
        try:
            ip_addr = socket.gethostbyname(domain)
            if ABUSEIPDB_API_KEY and "你的" not in ABUSEIPDB_API_KEY:
                abuse_url = "https://api.abuseipdb.com/api/v2/check"
                abuse_headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
                abuse_params = {"ipAddress": ip_addr, "maxAgeInDays": "90"}
                abuse_res = requests.get(abuse_url, headers=abuse_headers, params=abuse_params, timeout=8)
                
                if abuse_res.status_code == 200:
                    ip_score = abuse_res.json()['data']['abuseConfidenceScore']
                    report_details.append(f"🔍 IP 評分: `{ip_score}/100`")
                    if ip_score > 40:
                        danger_score += ip_score
                        report_details.append(f"🚩 AbuseIPDB 警告：此 IP 有攻擊舉報紀錄")
        except:
            report_details.append("⚠️ IP 解析失敗 (可能網域已失效)")

        # Whois 網域年資分析
        try:
            w = whois.whois(domain)
            c_date = w.creation_date
            if isinstance(c_date, list): c_date = c_date[0]
            
            if c_date:
                # 無時區格式計算
                days = (datetime.now() - c_date.replace(tzinfo=None)).days
                report_details.append(f"📅 網域年資: `{days}` 天")
                if days < 30:
                    danger_score += 50
                    report_details.append(f"🚩 網域極新，可能是剛建立的釣魚站")
        except:
            report_details.append("⚠️ 無法取得網域註冊資訊")

        # 4. VirusTotal 聯防引擎檢查
        if VT_API_KEY and "你的" not in VT_API_KEY:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            vt_headers = {"x-apikey": VT_API_KEY}
            vt_res = requests.get(vt_url, headers=vt_headers, timeout=8)
            if vt_res.status_code == 200:
                vt_stats = vt_res.json()['data']['attributes']['last_analysis_stats']
                malicious = vt_stats.get('malicious', 0)
                if malicious > 0:
                    danger_score += 100
                    report_details.append(f"🚨 VT 警告：有 {malicious} 家資安廠商將其列為黑名單")

        # 5. 綜合判定
        final_status = "✅ 安全"
        if danger_score >= 100: final_status = "💀 極度危險"
        elif danger_score >= 40: final_status = "⚠️ 高風險"

        full_message = (
            f"**【資安深度掃描報告】**\n"
            f"🌐 網域: `{domain}`\n"
            f"📍 解析 IP: `{ip_addr}`\n"
            f"📊 綜合判定: **{final_status}**\n"
            f"📝 詳情: " + (" | ".join(report_details))
        )
        return {"status": final_status, "message": full_message}

    except Exception as e:
        print(traceback.format_exc())
        return {"status": "錯誤", "message": f"❌ 大腦運算發生故障: {str(e)}"}

# 個資外洩 (Email/電話) 偵測
@app.post("/api/check_leak")
def check_leak(request: ContentRequest):
    raw_input = request.content.strip()
    input_type = identify_input(raw_input)
    search_term = raw_input

    # 電話自動轉換
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
        res = requests.get(
            "https://breachdirectory.p.rapidapi.com/passwords", 
            headers=headers, 
            params={"func": "auto", "term": search_term},
            timeout=10
        )
        data = res.json()
        found = data.get("found", 0)
        
        if found > 0:
            return {
                "status": "危險", 
                "message": f"🚨 **個資外洩警報！**\n這組 {input_type} (`{raw_input}`) 曾在 **{found}** 處外洩資料庫中出現過！建議立即檢查並更改密碼。"
            }
        return {"status": "安全", "message": f"✅ **掃描完成**\n這組 {input_type} (`{raw_input}`) 目前查無公開外洩紀錄。"}
    except:
        return {"status": "錯誤", "message": "❌ 無法連接外洩資料庫，請稍後再試。"}
