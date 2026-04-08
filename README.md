[abuse-api-README.md](https://github.com/user-attachments/files/26574806/abuse-api-README.md)
# AbuseIPDB Local API

A locally hosted REST API that replicates the AbuseIPDB v2 interface using
FastAPI and SQLite. Built as a self-contained threat intelligence backend for
the SOC IOC Reputation Checker project — no external accounts or rate limits
required during development and testing.

---

## Why this exists

The real AbuseIPDB API requires an internet connection and has a 1,000
requests/day free-tier limit. During development you want to run hundreds of
test lookups without burning your quota. This API mirrors the exact same
response format as AbuseIPDB v2, so the IOC checker connects to it with a
single URL change — no code refactoring needed.

---

## Features

- Full AbuseIPDB v2 response schema — drop-in compatible
- SQLite database — single file, no server process needed
- Automatic interactive API docs at `http://localhost:8000/docs`
- API key authentication mirroring real AbuseIPDB header auth
- Confidence score engine based on report volume and reporter diversity
- Seed script with realistic malicious, suspicious, and clean IP test data
- IP metadata support — country, ISP, usage type, TOR node flag

---

## Project structure

```
abuse-api/
├── api/
│   ├── __init__.py
│   ├── database.py      # SQLite setup, queries, confidence scoring
│   ├── models.py        # Pydantic request/response schemas
│   └── routes.py        # /check and /report endpoints
├── data/
│   └── reports.db       # SQLite database (auto-created on first run)
├── seed.py              # Populate DB with test data
├── main.py              # FastAPI app entry point
└── requirements.txt
```

---

## Quickstart

### 1. Install dependencies

```powershell
pip install fastapi uvicorn pydantic
```

### 2. Seed the database

```powershell
python seed.py
```

Expected output:

```
Seeding database...
  45.33.32.156   — 80 reports  (malicious)
  185.220.101.5  — 95 reports  (malicious / TOR)
  203.0.113.99   — 70 reports  (malicious)
  198.51.100.7   — 35 reports  (suspicious)
  8.8.8.8        —  0 reports  (clean)
  1.1.1.1        —  0 reports  (clean)
Done.
```

### 3. Start the API server

```powershell
python -m uvicorn main:app --reload --port 8000
```

You should see:

```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

Keep this terminal open — the server runs until you press Ctrl+C.

### 4. Open the interactive docs

Go to `http://localhost:8000/docs` in your browser. You can test every
endpoint with a visual form directly from there.

---

## API reference

### `GET /api/v2/check`

Check an IP address against the local abuse database.

**Headers**

| Header | Value |
|--------|-------|
| `Key`  | `test-key-123` (default) |

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ipAddress` | string | IP to check (required) |
| `maxAgeInDays` | int | Report window, default 90 |

**Example request**

```powershell
curl.exe -H "Key: test-key-123" "http://localhost:8000/api/v2/check?ipAddress=45.33.32.156"
```

**Example response**

```json
{
  "data": {
    "ipAddress": "45.33.32.156",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 85,
    "countryCode": "US",
    "usageType": "Data Center",
    "isp": "Linode LLC",
    "domain": "linode.com",
    "isTor": false,
    "totalReports": 80,
    "numDistinctUsers": 6,
    "lastReportedAt": "2025-03-30T10:22:01"
  }
}
```

---

### `POST /api/v2/report`

Submit a new abuse report for an IP.

**Headers**

| Header | Value |
|--------|-------|
| `Key`  | `test-key-123` |
| `Content-Type` | `application/json` |

**Request body**

```json
{
  "ip": "1.2.3.4",
  "categories": "18",
  "comment": "Brute force SSH attempts",
  "reporter_ip": "10.0.0.1"
}
```

**Category IDs** (matching real AbuseIPDB)

| ID | Category |
|----|----------|
| 4  | DDoS Attack |
| 14 | Port Scan |
| 18 | Brute Force |
| 22 | Hacking |

---

## Confidence score formula

```
volume_score    = min(total_reports × 3,  60)
diversity_bonus = min(distinct_reporters × 5, 40)
confidence      = min(volume_score + diversity_bonus, 100)
```

More reports from more independent sources = higher confidence.
TOR nodes are automatically floored at 80%.

---

## Connecting to the IOC checker

In your `ioc-checker` project, open `checker/abuseipdb.py` and change
one line:

```python
# Before
BASE = "https://api.abuseipdb.com/api/v2"

# After
BASE = "http://localhost:8000/api/v2"
```

Then update `.env`:

```
ABUSEIPDB_API_KEY=test-key-123
```

The IOC checker will now query your local API with zero other changes.

---

## MITRE ATT&CK coverage

| Technique | ID | How this API helps |
|-----------|----|--------------------|
| Brute Force | T1110 | Tracks and scores repeated auth failure reports |
| Active Scanning | T1595 | Captures port scan reports per IP |
| Gather Victim Network Info | T1590 | ISP and ASN metadata on each IP |

---

## Extending this project

**Add GeoIP enrichment** — integrate `geoip2` with the MaxMind GeoLite2
database to auto-populate country and ISP fields on every new report instead
of requiring manual metadata entry.

**Add a bulk check endpoint** — `POST /api/v2/bulk-check` accepting a list
of IPs and returning all results in one response. Useful for feeding entire
log files through at once.

**Add report expiry** — a background task using `asyncio` that deletes
reports older than 365 days to keep the database lean.

---

## Requirements

```
fastapi>=0.110.0
uvicorn>=0.29.0
pydantic>=2.0.0
```

Python 3.9+ required. No external internet connection needed once installed.

---

## Licence

MIT — use freely for learning, portfolio work, and home lab projects.
