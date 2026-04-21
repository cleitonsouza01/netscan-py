# netscan-py

A network scanner that discovers devices on your local network, probes web services, and optionally uses **AI (Google Gemini)** to flag default credentials and security risks.

## What it does

1. **nmap scan** — SYN + service/OS detection, top-1000 ports by default, broadened host discovery (ICMP + TCP/UDP ping probes) for firewalled hosts.
2. **Hostname resolution** — PTR, NetBIOS (`nbstat`), SMB (`smb-os-discovery`), RDP/HTTP NTLM challenge (`rdp-ntlm-info`, `http-ntlm-info`), system reverse DNS, LLMNR PTR fallback.
3. **Web probes** on common HTTP(S) ports — server header, page title, status code.
4. **AI analysis (optional)** — Gemini 2.5 Flash identifies device type, default credentials, risks, and recommendations.
5. **Reports** — rich console output, interactive HTML, JSON.

## Requirements

- Python 3.10+, `nmap` in `PATH`, root/admin (SYN scan and OS detection need raw sockets).

## Quick start

```bash
git clone <repo-url>
cd netscan-py
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Optional — enable AI analysis
cp .env-example .env      # then set GEMINI_API_KEY=...
# Free key: https://aistudio.google.com/apikey

python3 netscan-py.py --list-subnets         # list interfaces and subnets
sudo python3 netscan-py.py 192.168.1.0/24    # scan
```

## CLI options

| Flag | Purpose |
|------|---------|
| `-l`, `--list-subnets` | List interfaces and their CIDR subnets |
| `--ai` / `--no-ai` | Force AI on/off. Default: auto (on when `GEMINI_API_KEY` is set) |
| `--fast` | Top 100 ports only (quick triage) |
| `--all-ports` | All 65535 ports per host (slow) |
| `--no-ping` | Skip host discovery — treat every IP as alive |

At startup the script prints a status line so you know what's happening:

```
🤖 AI analysis: ENABLED — Gemini 2.5 Flash
Profile: common ports · discovery on · a /24 scan takes ~3–10 minutes
```

## HTML report

- **Severity-sorted** — per-host score from default creds, exposed admin UIs, and AI-flagged risks. Colored stripe and pill on every card; most-critical first.
- **Summary stats** — Live Hosts · Open Ports · Critical · Default Creds · Exposed Web · With Risks.
- **Filter chips** — All / Critical / High / Default Creds / Web Exposed / With Risks.
- **View toggle** — Cards (detailed) ↔ List (dense table).
- **Clickable port numbers** for HTTP(S) — open in a new tab.
- **Copy button** on default credentials.
- **Hostname source badge** — `RDNS` / `NETBIOS` / `SMB` / `RDP-NTLM` / `HTTP-NTLM` / `LLMNR`.
- Free-text search, empty state, back-to-top, responsive.

## Output files

| File | Description |
|------|-------------|
| `scan_report_<subnet>_<date>.html` | Interactive HTML report |
| `scan_results.json` | Hosts, ports, AI analysis |
| `scan.xml` | Raw nmap XML |

## Building a Windows .exe

On Windows with Python 3.10+:

```cmd
build.bat
```

Produces `dist\netscan.exe`. Place `.env` next to it. `nmap` must also be installed on the target machine.

## Project structure

```
netscan-py/
├── netscan-py.py       # Main scanner script
├── requirements.txt    # Python dependencies
├── build.bat           # Windows .exe build script
├── netscan-py.spec     # PyInstaller config
├── .env-example        # API key template
└── README.md
```

## License

For authorized security testing and educational use only. Always get permission before scanning networks you don't own.
