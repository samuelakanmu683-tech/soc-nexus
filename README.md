# soc-nexus
Security Operations platform for event monitoring, threat detection, alert triage, investigation, and incident response.
# SOC-Nexus

## Security Operations Center Threat Detection Platform

SOC-Nexus is a Python-based Security Operations Center (SOC) platform designed to ingest authentication events and detect suspicious activity using rule-based detection engineering.

The project demonstrates practical SOC analyst skills including security event ingestion, authentication monitoring, threat detection, alert generation, API development, and automated testing.

## Detection Capabilities

SOC-Nexus currently detects:

| Rule ID | Detection | Severity |
|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH |
| AUTH-002 | Successful Login Following Repeated Failures | HIGH |
| AUTH-003 | Multiple Sources Targeting Account | MEDIUM |

### AUTH-001 — SSH Brute Force

Detects repeated failed authentication attempts from the same source IP.

### AUTH-002 — Successful Login Following Repeated Failures

Detects a successful authentication following multiple failed attempts from the same source IP and username.

### AUTH-003 — Multiple Sources Targeting Account

Detects multiple source IP addresses generating failed authentication events against the same account.

## Architecture

```text
Security Event
     │
     ▼
FastAPI API
     │
     ▼
Event Storage
     │
     ▼
Detection Engine
     │
     ├── AUTH-001: Brute Force
     ├── AUTH-002: Success After Failures
     └── AUTH-003: Multiple Sources
     │
     ▼
Security Alerts
Technology Stack
Python
FastAPI
Uvicorn
Pytest
REST API
Rule-based detection engineering
Project Structure
soc-nexus/
├── backend/
│   ├── app/
│   │   ├── detector.py
│   │   ├── main.py
│   │   ├── models.py
│   │   └── storage.py
│   └── frontend/
├── tests/
│   └── test_detector.py
├── .gitignore
├── LICENSE
└── README.md
Running Locally
1. Create and activate a virtual environment
python -m venv .venv

Windows:

.venv\Scripts\activate
2. Install dependencies
pip install fastapi uvicorn pytest
3. Start the API
uvicorn backend.app.main:app --reload

The API will be available at:

http://127.0.0.1:8000

Interactive API documentation:

http://127.0.0.1:8000/docs
Testing

Run the automated test suite:

python -m pytest -q

Current test result:

4 passed
Demonstrated Detection Results

The detection engine has been tested successfully against simulated authentication activity.

AUTH-001 — SSH Brute Force

Five failed SSH authentication attempts from the same source generated a HIGH severity alert.

AUTH-002 — Successful Login Following Repeated Failures

Three failed authentication attempts followed by a successful login generated a HIGH severity alert.

AUTH-003 — Multiple Sources Targeting Account

Three different source IP addresses targeting the same account generated a MEDIUM severity alert.
## Detection Evidence

### AUTH-001 — SSH Brute Force

Five failed SSH authentication attempts from the same source generated a HIGH severity alert.

![AUTH-001 SSH Brute Force](auth-001-brute-force.png)

### AUTH-002 — Successful Login Following Repeated Failures

A successful login following repeated failed authentication attempts generated a HIGH severity alert.

![AUTH-002 Successful Login](auth-002-success-after-failures.png)

### AUTH-003 — Multiple Sources Targeting Account

Three different source IP addresses targeting the same account generated a MEDIUM severity alert.

![AUTH-003 Multiple Sources](auth-003-multiple-sources.png)
Security Considerations

This project uses simulated security events for demonstration and educational purposes.

No real credentials, production authentication logs, or private user information should be included in this repository.

Future Improvements

Planned improvements include:

Persistent database storage
Authentication and authorization
Alert dashboard
Real-time event streaming
Additional detection rules
Incident management workflow
Docker deployment
SIEM integration
Author

Samuel Akanmu

Cybersecurity Analyst | SOC & Threat Detection

SOC-Nexus demonstrates practical security monitoring, detection engineering, API development, and automated testing in a portfolio-ready SOC project.
