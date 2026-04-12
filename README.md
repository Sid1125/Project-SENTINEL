# 🛡️ Project SENTINEL

**Security Engine for Network Threat Intelligence, Education, Logging & Learning**

An AI-powered, offline-capable cybersecurity platform with natural language control. Designed to bring enterprise-grade network protection to homes and small businesses.

---

## Features

### Core Capabilities
- **Network Discovery** - ARP scanning + Nmap port enumeration
- **Threat Intelligence** - Local CVE database and vulnerability analysis
- **AI-Powered Detection** - ML-based anomaly detection
- **Natural Language Interface** - Control SENTINEL with plain English commands
- **Real-time Dashboard** - Live network monitoring via React UI
- **WebSocket Communication** - Instant updates and responsive UI

### Architecture
```
SENTINEL/
├── backend/           # Python FastAPI server
│   ├── core/         # Scanner, threat analysis
│   ├── ai/           # LLM + NLP processing
│   ├── api/          # REST + WebSocket endpoints
│   └── models/       # Database schemas
├── frontend/         # React + Tailwind dashboard
├── venv/             # Python virtual environment
└── docs/             # ROADMAP and documentation
```

---

## Prerequisites

### Required Software
- **Python 3.11+** (Tested with 3.14)
- **Node.js 18+**
- **PostgreSQL 14+** - Must be running with a user that has access to create databases
- **Nmap** - Must be installed and in PATH ([nmap.org](https://nmap.org))

### Optional (for AI/NLP)
- **Ollama** - Local LLM runtime ([ollama.ai](https://ollama.ai))

---

## Quick Start (Windows)

### Option 1: Automated Setup
```bash
setup.bat
```

### Option 2: Manual Setup

```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate virtual environment
venv\Scripts\activate

# 3. Install dependencies
pip install -r backend\requirements.txt

# 4. Install Nmap
# Download from https://nmap.org/download.html
# Add to PATH or install to C:\Program Files\Nmap
```

### Running SENTINEL

```bash
# Terminal 1: Start Backend
venv\Scripts\python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Start Frontend
cd frontend
npm install
npm run dev
```

### Access Dashboard
Open **http://localhost:3000** in your browser.

---

## Usage

### Dashboard Controls
- Click **Quick Scan** to discover devices on your network
- Select devices to view port details and risk analysis
- Use **AI Control** tab for natural language commands

### NLP Commands
Try these commands in the AI Control panel:
```
"Scan my network"
"Check for threats on 192.168.1.1"
"What devices are on my network?"
"Show status"
"Help"
```

---

## Configuration

### Environment Variables

Create `backend/.env` (optional):
```env
DATABASE_URL=sqlite:///sentinel.db
LLM_HOST=http://localhost:11434
LLM_MODEL=phi
LOG_LEVEL=INFO
```

### Settings Panel
Access via Dashboard → Settings tab to configure:
- LLM host/model
- Database connection
- Scan timeout
- Auto-defense options

---

## Project Status

### MVP ✅ Complete
- Network scanner with ARP + Nmap
- Threat intelligence engine
- FastAPI + WebSocket backend
- React dashboard with real-time updates
- Local LLM integration (Phi-2 via Ollama)
- NLP intent parsing
- SQLite database (no PostgreSQL required)

### In Progress
- ML-based anomaly detection
- Auto-defense automation

### Remaining (see docs/ROADMAP.md)
- IDS/IPS integration
- Honeypot deployment
- Comprehensive reporting
- Omega Protocol (offensive module)

---

## Troubleshooting

### "nmap program was not found in path"
- Download Nmap from https://nmap.org
- Add to PATH or install to `C:\Program Files\Nmap`

### "Database connection failed"
- Will automatically use SQLite (no setup needed)

### "LLM not available"
- Install Ollama and run: `ollama pull phi`
- Or continue without AI (rule-based NLP still works)

### Port already in use
- Backend defaults to port 8000
- Frontend defaults to port 3000
- Change in configuration files if needed

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11+, FastAPI, SQLAlchemy |
| Database | SQLite (default), PostgreSQL (optional) |
| AI/NLP | Phi-2 (via Ollama), Transformers |
| Network | Nmap, Scapy, Netaddr |
| Frontend | React 18, Tailwind CSS, Recharts |
| Realtime | WebSocket (Socket.IO) |

---

## License

This project is for educational and defensive purposes only.

---

*"Security for the people. With claws." - Project SENTINEL*
