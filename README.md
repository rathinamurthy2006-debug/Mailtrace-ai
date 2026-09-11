# MailTrace AI

**Email Forensics & Phishing Detection Tool**
*Built for Smart India Hackathon 2026 — SIH26106 (Blockchain & Cybersecurity)*

MailTrace AI analyzes `.eml` email files to detect phishing indicators, extract forensic evidence (IPs, URLs, headers, attachments), assess risk using rule-based and NLP heuristics, and visualize sender IP geolocation on an interactive map — all while preserving evidence integrity via SHA-256 hashing.

---

## Features

- **Email Parsing** — extracts sender/recipient details, subject, body, headers, attachments, and full `Received:` header relay chain from `.eml` files
- **Risk Scoring Engine** — rule-based detection of phishing indicators:
  - Suspicious keyword/phrase detection (urgency language, credential requests, etc.)
  - NLP-based typosquatted domain detection using Levenshtein edit-distance against known brand names
  - Sender vs Reply-To domain mismatch detection
  - SPF / DKIM / DMARC authentication result checks
  - Suspicious URL pattern matching
  - Dangerous attachment type detection
- **IP Geolocation** — extracts IPs from email headers and plots their approximate location on an interactive map (Leaflet.js + ip-api.com)
- **Evidence Integrity** — SHA-256 hashing of uploaded evidence for forensic chain-of-custody
- **Case Persistence** — stores case metadata in PostgreSQL for future retrieval and multi-case tracking
- **Forensic Report Export** — downloadable JSON report per analyzed case

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python (Flask) |
| Frontend | HTML5, CSS3, JavaScript (vanilla) |
| Email Parsing | Python `email` standard library |
| Risk Detection | Rule-based engine + NLP heuristics (keyword matching, Levenshtein-distance domain analysis) |
| Geolocation | ip-api.com + Leaflet.js |
| Database | PostgreSQL |
| Reporting | JSON export with SHA-256 evidence hashing |

### Roadmap (Phase 2)
- ML-based phishing classifier trained on labeled datasets
- Threat intel API integration (VirusTotal, AbuseIPDB) for IP/URL reputation scoring
- React-based analyst dashboard
- Multi-case investigation history and search

---

## Project Structure
mailtrace-ai/
├── app.py # Main Flask application & routes
├── email_parser.py # .eml parsing, IP/URL extraction
├── risk_engine.py # Rule-based + NLP risk scoring engine
├── db.py # PostgreSQL connection & case persistence
├── templates/
│ ├── index.html # Main dashboard UI
│ └── map.html # Standalone geolocation map view
├── static/
│ ├── app.js # Frontend logic
│ └── style.css # Styling
├── uploads/ # Uploaded .eml evidence files
├── reports/ # Generated JSON forensic reports
└── samples/ # Sample .eml test files


---

## Setup & Installation

### Prerequisites
- Python 3.10+
- PostgreSQL

### 1. Clone and set up virtual environment
```bash
git clone <repo-url>
cd mailtrace-ai
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies
```bash
pip install flask requests psycopg2-binary
```

### 3. Set up PostgreSQL
```bash
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER mailtrace WITH PASSWORD 'mailtrace123';"
sudo -u postgres psql -c "CREATE DATABASE mailtrace_db OWNER mailtrace;"
```

### 4. Run the application
```bash
python3 app.py
```

Visit **http://127.0.0.1:5000** in your browser.

---

## Usage

1. Upload a `.eml` email file via the dashboard
2. View extracted sender identity, authentication results, and risk indicators
3. Review Indicators of Compromise (URLs, IPs, attachments)
4. Click **"Show on Map"** to geolocate extracted sender IPs
5. Download the full forensic JSON report for offline analysis
6. Case metadata is automatically stored in PostgreSQL for future reference

---

## Team

**Blockchain & Cybersecurity**

---

## Disclaimer

This is a hackathon prototype built for demonstration purposes. Risk scoring uses heuristic and rule-based detection, not a trained machine learning model. It is not intended for production security use without further validation and testing.
