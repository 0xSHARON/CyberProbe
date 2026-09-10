# 🛡️ CyberProbe v2.5 PRO

### Web Vulnerability Scanner & Penetration Testing Suite

```text
 ██████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
██╔═████╗╚██╗██╔╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██║██╔██║ ╚███╔╝ ███████╗███████║███████║██████╔╝██║   ██║██╔██╗ ██║
████╔╝██║ ██╔██╗ ╚════██║██╔══██║██╔══██║██╔══██╗██║   ██║██║╚██╗██║
╚██████╔╝██╔╝ ██╗███████║██║  ██║██║  ██║██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

                     0x S H A R O N
                 // SECURITY RESEARCHER //
```

> **CyberProbe v2.5 PRO** is a Node.js-based web security assessment platform designed to perform authorized vulnerability scanning, security analysis, and penetration-testing workflows against web applications.

---

## ⚠️ Legal & Ethical Use

CyberProbe is intended **only for authorized security testing**.

Use this software against:

* Systems you own
* Applications you are authorized to assess
* Lab environments
* CTF environments
* Security research targets where you have explicit permission

**Do not scan or attack systems without authorization.**

The developer assumes no responsibility for unauthorized or illegal use of this software.

---

## 🚀 Features

### 🔍 Web Vulnerability Scanning

CyberProbe can be used as a security assessment engine for identifying potential web application weaknesses.

Supported assessment areas can include:

* Security headers
* HTTP configuration
* SSL/TLS configuration
* Common web vulnerabilities
* Authentication weaknesses
* Input validation issues
* Information disclosure
* Misconfiguration
* Technology detection
* Endpoint analysis
* Risk scoring

---

### 📡 Real-Time Scan Streaming

CyberProbe provides a Server-Sent Events (SSE) endpoint for streaming scan activity to the frontend.

```http
GET /api/scan-stream
```

Example:

```text
/api/scan-stream?url=https://example.com&profile=Full%20Pen-Test
```

The frontend can receive events such as:

```text
status
log
complete
error
```

This allows the interface to display a live security-terminal experience while a scan is running.

---

## 🧠 Scan Profiles

CyberProbe supports scan profiles through the `scanProfile` parameter.

Example:

```json
{
  "targetUrl": "https://example.com",
  "scanProfile": "Full Pen-Test"
}
```

Possible profiles can be implemented according to your scanner configuration, for example:

```text
Quick Scan
Standard Scan
Full Pen-Test
Passive Recon
Security Headers
API Assessment
```

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │      Web Browser     │
                    │   CyberProbe UI      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Express Server    │
                    │      server.js       │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       /api/status        /api/scan       /api/scan-stream
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │  CyberProbe Engine   │
                    │      scanner.js      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Scan Results       │
                    │ Risk / Findings      │
                    │ Counts / Metadata     │
                    └──────────────────────┘
```

---

## 📁 Project Structure

```text
CyberProbe/
│
├── server.js
├── scanner.js
├── package.json
├── package-lock.json
│
├── public/
│   ├── index.html
│   ├── css/
│   ├── js/
│   ├── assets/
│   └── ...
│
├── reports/
│
└── README.md
```

### Core Files

| File           | Purpose                          |
| -------------- | -------------------------------- |
| `server.js`    | Express API server               |
| `scanner.js`   | CyberProbe scanning engine       |
| `package.json` | Node.js dependencies and scripts |
| `public/`      | Frontend application             |
| `reports/`     | Generated security reports       |
| `README.md`    | Project documentation            |

---

# ⚙️ Installation

## 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberProbe.git
```

Enter the project:

```bash
cd CyberProbe
```

---

## 2. Install Dependencies

Make sure Node.js is installed.

Check:

```bash
node --version
```

Then install dependencies:

```bash
npm install
```

---

## 3. Configure Environment

Create a `.env` file if your scanner requires environment variables.

Example:

```env
PORT=3000
NODE_ENV=development
```

Never commit secrets or API keys to GitHub.

---

# ▶️ Running CyberProbe

Start the server:

```bash
npm start
```

Or, if your project uses a development script:

```bash
npm run dev
```

The server will be available at:

```text
http://localhost:3000
```

You should see:

```text
====================================================

                     0x S H A R O N
                 // SECURITY RESEARCHER //

====================================================
🛡️  CYBERPROBE v2.5 PRO - Security Engine Online
📡 Server running at http://localhost:3000
🎯 Real Web Vulnerability & Penetration Suite Ready
⚡ 0xSHARON // INITIALIZING SECURITY PROTOCOLS...
====================================================
```

---

# 🔌 API Documentation

## Health / Status

```http
GET /api/status
```

Example:

```bash
curl http://localhost:3000/api/status
```

Response:

```json
{
  "name": "CyberProbe Engine",
  "version": "2.5 PRO",
  "status": "Standby",
  "standards": [
    "OWASP 2024",
    "CWE",
    "NIST SP 800-115"
  ],
  "activeScans": 0
}
```

---

# 🔎 Start a Scan

```http
POST /api/scan
```

Request:

```json
{
  "targetUrl": "https://example.com",
  "scanProfile": "Full Pen-Test"
}
```

Example:

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"targetUrl\":\"https://example.com\",\"scanProfile\":\"Full Pen-Test\"}"
```

---

# 📡 Streaming Scan

```http
GET /api/scan-stream
```

Parameters:

| Parameter | Required | Description           |
| --------- | -------: | --------------------- |
| `url`     |      Yes | Authorized target URL |
| `profile` |       No | Scan profile          |

Example:

```text
http://localhost:3000/api/scan-stream?url=https://example.com&profile=Full%20Pen-Test
```

The endpoint uses:

```text
Server-Sent Events (SSE)
```

Example event:

```text
event: status
data: {"state":"initializing","message":"Initializing engine..."}
```

Log events:

```text
event: log
data: {"message":"Checking security headers..."}
```

Completion:

```text
event: complete
data: {...}
```

---

# 📜 Scan History

CyberProbe keeps the most recent scan summaries in memory.

```http
GET /api/history
```

Example:

```bash
curl http://localhost:3000/api/history
```

The history contains:

```json
[
  {
    "id": "123456789",
    "targetUrl": "https://example.com",
    "riskScore": 42,
    "counts": {},
    "timestamp": "2026-09-10T00:00:00.000Z"
  }
]
```

> Current history storage is **in-memory** and will reset when the Node.js process restarts.

---

# 🛡️ Security Standards

CyberProbe organizes security findings around commonly used security frameworks and references, including:

### OWASP

```text
OWASP Web Application Security
```

### CWE

```text
Common Weakness Enumeration
```

### NIST

```text
NIST SP 800-115
Technical Guide to Information Security Testing and Assessment
```

These references can be mapped to individual scanner findings as the engine develops.

---

# 📊 Risk Scoring

CyberProbe can assign a risk score based on discovered findings.

A production implementation should consider factors such as:

```text
Severity
Exploitability
Impact
Confidence
Affected Endpoint
Authentication Requirement
Exposure
```

Example severity categories:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

---

# 🧪 Development

Run the project in development mode:

```bash
npm run dev
```

Recommended development workflow:

```text
1. Start Node.js server
2. Open CyberProbe dashboard
3. Select authorized target
4. Select scan profile
5. Start scan
6. Monitor SSE terminal
7. Review findings
8. Generate report
```

---

# 🔐 Production Security Recommendations

Before deploying CyberProbe publicly:

* Add authentication
* Add authorization/RBAC
* Restrict scanner access
* Validate target URLs
* Implement SSRF protections
* Rate-limit scan requests
* Add request logging
* Add scan timeouts
* Add concurrency limits
* Sanitize user input
* Protect internal network ranges
* Prevent localhost/private-IP scanning where appropriate
* Store reports securely
* Add audit logging
* Use HTTPS
* Configure secure CORS
* Add CSRF protection where applicable
* Do not expose scanner administration endpoints publicly

### Important

A public vulnerability scanner can become an SSRF or network-probing service if arbitrary target URLs are accepted without proper controls.

For production deployments, target validation and network egress restrictions are essential.

---

# 🐳 Docker

Example Docker workflow:

```bash
docker build -t cyberprobe .
```

Run:

```bash
docker run -p 3000:3000 cyberprobe
```

Then open:

```text
http://localhost:3000
```

---

# 🌐 Deployment

CyberProbe can be deployed to Node.js-compatible hosting platforms.

Typical deployment architecture:

```text
                    Internet
                       │
                       ▼
                ┌─────────────┐
                │ Reverse     │
                │ Proxy / TLS │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ CyberProbe  │
                │ Node.js     │
                └──────┬──────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       Scanner Engine        Database
```

For production, replace the in-memory scan history with a persistent database such as PostgreSQL.

---

# 🧭 Roadmap

## v2.5 PRO

* [x] Express backend
* [x] REST API
* [x] Scan endpoint
* [x] SSE scan streaming
* [x] Scan history
* [x] Risk scoring
* [x] Security-engine terminal
* [x] 0xSHARON branding

## Future

* [ ] Authentication & RBAC
* [ ] PostgreSQL database
* [ ] Persistent scan history
* [ ] PDF reporting
* [ ] HTML reporting
* [ ] Scheduled scans
* [ ] API security testing
* [ ] Subdomain discovery
* [ ] Technology fingerprinting
* [ ] Custom scan profiles
* [ ] Team collaboration
* [ ] Audit logs
* [ ] Webhook notifications
* [ ] Docker deployment
* [ ] CI/CD integration

---

# 👨‍💻 Author

### 0xSHARON

```text
0xSHARON
Security Researcher
CyberProbe Project
```

---

# ⭐ Contributing

Contributions are welcome.

```bash
git checkout -b feature/new-feature
```

Make your changes, test them, then:

```bash
git add .
git commit -m "Add new security feature"
git push origin feature/new-feature
```

Create a Pull Request on GitHub.

---

# 📄 License

Choose an appropriate open-source or proprietary license before publishing the project.

Example:

```text
MIT License
```

If CyberProbe contains proprietary scanning logic or is intended as a commercial product, consider using a proprietary license instead.

---

## 🛡️ CyberProbe

```text
                    ╔══════════════════════════╗
                    ║      0xSHARON             ║
                    ║   SECURITY RESEARCHER     ║
                    ╠══════════════════════════╣
                    ║    CYBERPROBE v2.5 PRO    ║
                    ║                            ║
                    ║  WEB SECURITY ANALYSIS    ║
                    ║  VULNERABILITY SCANNING   ║
                    ║  PENETRATION TESTING      ║
                    ╚══════════════════════════╝
```

**Scan smart. Test responsibly. Secure everything.**
