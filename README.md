# netscan-py

A network scanner that discovers devices on your local network, probes web services, and uses **AI (Google Gemini)** to identify security risks like default passwords.

## What it does

1. **Scans your network** with nmap (SYN scan + service/OS detection)
2. **Probes web ports** (80, 443, 8080, etc.) to grab server info and page titles
3. **AI analysis** sends each device's info to Gemini 2.5 Flash to identify:
   - Device type
   - Known default credentials (user/pass)
   - Security risks
   - Recommendations
4. **Generates reports** in three formats:
   - Rich console output with colors
   - Interactive HTML report (dark theme, searchable)
   - JSON file for programmatic use

## Requirements

- **Python 3.10+**
- **nmap** installed and in PATH
- **Root/admin privileges** (nmap needs raw sockets for SYN scan)

## Quick start

### 1. Clone and install

```bash
git clone <repo-url>
cd netscan-py
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

### 2. Set up your API key

```bash
cp .env-example .env
```

Edit `.env` and add your Google Gemini API key:

```
GEMINI_API_KEY=your-api-key-here
```

Get a free key at [Google AI Studio](https://aistudio.google.com/apikey).

> **Note:** The AI analysis step is optional. If no key is set, the scan runs normally and just skips the AI part.

### 3. Run

First, find your available subnets:

```bash
python3 netscan-py.py --list-subnets
```

This shows all network interfaces with their CIDR subnets:

```
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Interface ┃ IP Address    ┃ Netmask       ┃ Subnet (CIDR)    ┃ Status   ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ en0       │ 192.168.1.100 │ 255.255.255.0 │ 192.168.1.0/24   │ active   │
└───────────┴───────────────┴───────────────┴──────────────────┴──────────┘
```

Then scan using one of the listed subnets:

```bash
sudo python3 netscan-py.py 192.168.1.0/24
```

## Output files

After a scan, you'll find:

| File | Description |
|------|-------------|
| `scan_report_<subnet>_<date>.html` | Interactive HTML report (open in browser) |
| `scan_results.json` | Raw JSON with all host data + AI analysis |
| `scan.xml` | Raw nmap XML output |

## Example output

```
nmap: 100%|████████████████████| 3m12s elapsed, ETA 0:00:00
✓ nmap scan complete

web probes: 8/8 [00:03]
LLM analysis: 6/6 [00:12]

┌─────────────────────────────┐
│ Found 6 live hosts          │
└─────────────────────────────┘

192.168.1.76 (unknown5803fb2f3bd0.attlocal.net)  —  🌐 Web server / IoT
  MAC: 58:03:FB:2F:3B:D0   Vendor: Hangzhou Hikvision Digital Technology
  OS:  Linux 3.2 - 4.14
  Port   Service   Product / Version                      Web info
  80/tcp http      Hikvision Network Video Recorder admin  [200] DNVRS-Webs
  🤖 AI Analysis: Hikvision Network Video Recorder (NVR)
  ⚠ Default credentials: admin:12345, admin:admin, root:hikvision
    • Use of known default credentials (if not changed)
    • Exposed web administration interface
    ✓ Change all default credentials immediately
    ✓ Isolate the device on a dedicated VLAN
```

## Building a Windows .exe

On a Windows machine with Python 3.10+:

```cmd
build.bat
```

This produces `dist\netscan.exe`. Place your `.env` file next to the `.exe`.

> **Important:** nmap must also be installed on the Windows machine.

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
