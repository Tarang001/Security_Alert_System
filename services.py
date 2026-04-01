import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "")


def get_virustotal_score(ip):
    """Returns malicious score (0-100) from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return 0

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        if total == 0:
            return 0
        return round((malicious / total) * 100, 2)

    except Exception:
        return 0


def get_ipinfo(ip):
    """Returns country and ISP from IPinfo."""
    try:
        token_param = f"?token={IPINFO_API_KEY}" if IPINFO_API_KEY else ""
        url = f"https://ipinfo.io/{ip}/json{token_param}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        return {
            "country": data.get("country", "Unknown"),
            "isp": data.get("org", "Unknown"),
        }

    except Exception:
        return {"country": "Unknown", "isp": "Unknown"}


def enrich_ip(ip):
    """Combines VirusTotal + IPinfo data for a single IP."""
    score = get_virustotal_score(ip)
    geo = get_ipinfo(ip)

    return {
        "ip": ip,
        "country": geo["country"],
        "isp": geo["isp"],
        "score": score,
    }