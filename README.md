# Security Alert Automation System

A simple SOC (Security Operations Center) automation tool that enriches and classifies IP addresses using VirusTotal and IPinfo.

---

## What It Does

1. Accepts one or more IP addresses as input
2. Enriches each IP with threat data (VirusTotal) and geolocation (IPinfo)
3. Classifies each IP as **Malicious**, **Suspicious**, or **Safe**
4. Returns results via a clean web UI or JSON API

---

## Project Structure

```
security-alert-system/
├── app.py            # Flask routes
├── services.py       # VirusTotal + IPinfo API calls
├── utils.py          # IP validation + classification rules
├── requirements.txt
├── .env.example
├── README.md
└── templates/
    └── index.html    # Web UI
```

---

## Local Setup

### 1. Clone and install dependencies

```bash
git clone <your-repo-url>
cd security-alert-system
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add your keys
```

Get free API keys:
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **IPinfo**: https://ipinfo.io/account/home

> **Note**: The app works without API keys — IPs will return score=0 and country/ISP="Unknown".

### 3. Run the app

```bash
python app.py
```

Open http://localhost:5000 in your browser.

---

## Using the Web UI

1. Go to http://localhost:5000
2. Enter IP addresses in the textarea (comma-separated)
3. Click **Run Analysis**
4. View the results table

---

## Using the API

### Analyze IPs (POST /analyze)

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"ips": ["8.8.8.8", "1.1.1.1"]}'
```

**Response:**
```json
{
  "results": [
    {
      "ip": "8.8.8.8",
      "country": "US",
      "isp": "AS15169 Google LLC",
      "score": 0,
      "status": "Safe"
    }
  ]
}
```

**Error response:**
```json
{
  "error": "Invalid IP address(es): 999.999.999.999"
}
```

---

## Classification Rules

| Condition                    | Status      |
|-----------------------------|-------------|
| Malicious score > 80%       | Malicious   |
| ISP contains "Tor"          | Suspicious  |
| Otherwise                   | Safe        |

---

## Tech Stack

- Python 3 + Flask
- requests (API calls)
- python-dotenv (env management)
- gunicorn (production server)
