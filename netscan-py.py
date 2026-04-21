#!/usr/bin/env python3
"""
Network scanner: wraps nmap, probes HTTP services, outputs console + HTML report.
Usage: sudo python3 netscan.py 192.168.1.0/24
       python3 netscan.py --list-subnets
"""
import argparse
import ipaddress
import os
import re
import socket
from tqdm import tqdm
import subprocess
import sys
import json
import html
import datetime
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv
import litellm

# When running as .exe, look for .env next to the executable
if getattr(sys, 'frozen', False):
    _base_dir = os.path.dirname(sys.executable)
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_base_dir, ".env"))

console = Console()

# ---------- nmap ----------
def run_nmap(
    target: str,
    xml_out: str = "scan.xml",
    port_mode: str = "common",  # "fast" | "common" | "all"
    skip_ping: bool = False,
) -> str:
    console.print(f"[cyan]Running nmap on {target}...[/cyan]")
    cmd = ["nmap", "-sS", "-sV", "-O", "--open",
           "--script", "nbstat,smb-os-discovery,rdp-ntlm-info,http-ntlm-info"]
    if skip_ping:
        cmd.append("-Pn")
    else:
        # Broader host discovery: ICMP echo + TCP SYN/ACK on common admin ports + UDP pings.
        # Catches devices that block ICMP but respond on TCP, and vice versa.
        cmd += ["-PE", "-PS22,80,135,139,443,445,3389,8080", "-PA80,443", "-PU53,137,161"]
    if port_mode == "fast":
        cmd.append("-F")  # top 100
        est = "1–3 minutes"
    elif port_mode == "all":
        cmd.append("-p-")  # 1-65535
        est = "30–90 minutes"
    else:  # common
        # nmap's default: top 1000 ports. No flag needed.
        est = "3–10 minutes"
    cmd += ["-T4", "-v", "--stats-every", "3s", "-oX", xml_out, target]
    profile = f"{port_mode} ports · {'skip ping' if skip_ping else 'discovery on'}"
    console.print(f"[dim]Profile: {profile} · a /24 scan takes ~{est}[/dim]")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    pct_re = re.compile(r"About ([\d.]+)% done")
    phase_re = re.compile(r"(\w[\w ]*Scan) Timing")
    bar = tqdm(
        total=100, desc="nmap", unit="%",
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {elapsed} elapsed, ETA {remaining} {postfix}",
    )
    current = 0.0
    phase = "starting"
    unmatched: list[str] = []

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line or "Illegal character" in line:
                continue

            m = pct_re.search(line)
            if m:
                pct = float(m.group(1))
                delta = pct - current
                if delta > 0:
                    bar.update(delta)
                    current = pct
                bar.set_postfix_str(phase)
                continue

            m = phase_re.search(line)
            if m:
                phase = m.group(1)
                bar.set_postfix_str(phase)
                continue

            if "Discovered open port" in line:
                bar.write(f"  ✓ {line.split(']')[-1].strip()}")
            elif "Nmap scan report for" in line:
                bar.write(f"  → {line.replace('Nmap scan report for ', 'host: ')}")
            else:
                unmatched.append(line)
    except KeyboardInterrupt:
        proc.terminate()
        bar.close()
        console.print("[red]Scan interrupted[/red]")
        sys.exit(1)

    proc.wait()
    if current < 100:
        bar.update(100 - current)
    bar.close()

    if proc.returncode != 0:
        console.print(f"[red]nmap exited with code {proc.returncode}[/red]")
        if unmatched:
            console.print(Panel("\n".join(unmatched[-20:]), title="nmap output", border_style="red"))
        joined = "\n".join(unmatched)
        needs_root = (
            "requires root privileges" in joined
            or "requires privileged" in joined
            or "Operation not permitted" in joined
            or "only works if you are root" in joined
        )
        is_root = getattr(os, "geteuid", lambda: 0)() == 0
        if needs_root and not is_root:
            console.print(
                "[yellow]Hint:[/yellow] this scan uses [bold]-sS[/bold] (SYN) and "
                "[bold]-O[/bold] (OS detection), which need raw sockets. "
                f"Re-run with sudo:\n  [cyan]sudo {' '.join(sys.argv)}[/cyan]"
            )
        sys.exit(1)
    console.print("[green]✓ nmap scan complete[/green]\n")
    return xml_out

def parse_nmap_xml(xml_file: str) -> list[dict]:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = os_name = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor", "Unknown")

        # Collect (source, name) candidates from every hostname source nmap provided.
        candidates: list[tuple[str, str]] = []
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                name = hn.get("name")
                if name:
                    candidates.append(("rDNS", name))
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "") or ""
                if sid == "nbstat":
                    m = re.search(r"NetBIOS name:\s*([^,\n<]+)", output)
                    if m:
                        candidates.append(("NetBIOS", m.group(1).strip()))
        # Port scripts: smb-os-discovery (SMB), rdp-ntlm-info (RDP 3389),
        # http-ntlm-info (WinRM 5985, IIS, etc.). NTLM challenge parsing works
        # on modern Windows even when NBSTAT/SMB null sessions are blocked.
        ports_elem_for_scripts = host.find("ports")
        if ports_elem_for_scripts is not None:
            for port in ports_elem_for_scripts.findall("port"):
                for script in port.findall("script"):
                    sid = script.get("id", "")
                    output = script.get("output", "") or ""
                    if sid == "smb-os-discovery":
                        m = re.search(r"\bFQDN:\s*([^\s,\n]+)", output)
                        if m:
                            candidates.append(("SMB", m.group(1).strip()))
                        m = re.search(r"NetBIOS computer name:\s*([^\s\\,\n]+)", output)
                        if m:
                            candidates.append(("SMB", m.group(1).strip()))
                    elif sid in ("rdp-ntlm-info", "http-ntlm-info"):
                        src = "RDP-NTLM" if sid == "rdp-ntlm-info" else "HTTP-NTLM"
                        m = re.search(r"DNS_Computer_Name:\s*([^\s\n]+)", output)
                        if m:
                            candidates.append((src, m.group(1).strip()))
                        m = re.search(r"NetBIOS_Computer_Name:\s*([^\s\n]+)", output)
                        if m:
                            candidates.append((src, m.group(1).strip()))

        # Prefer FQDNs (anything with a dot) over short names.
        hostname = None
        hostname_source = None
        if candidates:
            fqdns = [c for c in candidates if "." in c[1]]
            best = fqdns[0] if fqdns else candidates[0]
            hostname_source, hostname = best

        os_elem = host.find("os")
        if os_elem is not None:
            match = os_elem.find("osmatch")
            if match is not None:
                os_name = match.get("name")
        ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "extrainfo": service.get("extrainfo", "") if service is not None else "",
                })
        hosts.append({
            "ip": ip, "hostname": hostname, "hostname_source": hostname_source,
            "mac": mac, "vendor": vendor, "os": os_name, "ports": ports,
        })
    return hosts


def _reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name.strip() or None
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(prev)


def _dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("ascii", errors="replace")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _dns_decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS-format name at offset. Handles pointer compression.
    Returns (name, offset_after_this_field)."""
    labels: list[str] = []
    return_offset = None
    seen = set()
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if return_offset is None:
                return_offset = offset + 2
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen:  # malformed / loop guard
                break
            seen.add(ptr)
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (return_offset if return_offset is not None else offset)


def _llmnr_ptr(ip: str, timeout: float = 1.5) -> str | None:
    """Unicast LLMNR PTR query to UDP/5355 on the target host.
    Works on Windows hosts with LLMNR enabled (default) when NetBIOS/SMB
    disclosure is blocked."""
    import struct
    import random as _rand
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return None
        qname = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        tid = _rand.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
        question = _dns_encode_name(qname) + struct.pack(">HH", 12, 1)  # PTR, IN
        packet = header + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, 5355))
            data, _ = sock.recvfrom(2048)
        if len(data) < 12:
            return None
        resp_tid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if resp_tid != tid or an == 0:
            return None
        offset = 12
        for _ in range(qd):
            _, offset = _dns_decode_name(data, offset)
            offset += 4  # QTYPE + QCLASS
        _, offset = _dns_decode_name(data, offset)  # answer NAME
        atype, _aclass, _ttl, _rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if atype != 12:  # PTR
            return None
        name, _ = _dns_decode_name(data, offset)
        name = name.rstrip(".")
        return name or None
    except (OSError, struct.error, IndexError):
        return None


def _resolve_hostname(ip: str) -> tuple[str, str] | None:
    """Try reverse DNS first, then LLMNR PTR as fallback."""
    name = _reverse_dns(ip, timeout=2.0)
    if name:
        return (name, "rDNS")
    name = _llmnr_ptr(ip, timeout=1.5)
    if name:
        return (name, "LLMNR")
    return None


def enrich_hostnames(hosts: list[dict]) -> None:
    """Fill in hostnames via reverse DNS, falling back to LLMNR."""
    missing = [h for h in hosts if not h.get("hostname") and h.get("ip")]
    if not missing:
        return
    console.print(f"[cyan]Resolving hostnames (rDNS → LLMNR) for {len(missing)} unnamed hosts...[/cyan]")
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_resolve_hostname, h["ip"]): h for h in missing}
        with tqdm(total=len(futures), desc="resolve", unit="host") as bar:
            for fut in as_completed(futures):
                host = futures[fut]
                result = fut.result()
                if result:
                    host["hostname"], host["hostname_source"] = result
                bar.update(1)

# ---------- enrichment ----------
def guess_device_type(host: dict) -> tuple[str, str]:
    """Return (emoji, label)."""
    vendor = (host.get("vendor") or "").lower()
    os_name = (host.get("os") or "").lower()
    ports = {p["port"] for p in host["ports"]}
    if any(v in vendor for v in ["apple", "iphone", "ipad"]):
        return ("📱", "Apple device")
    if any(v in vendor for v in ["samsung", "xiaomi", "huawei"]):
        return ("📱", "Android / Mobile")
    if any(v in vendor for v in ["tp-link", "netgear", "asus", "ubiquiti", "mikrotik", "cisco"]):
        return ("🌐", "Router / Network gear")
    if "raspberry" in vendor:
        return ("🍓", "Raspberry Pi")
    if any(v in vendor for v in ["hp", "canon", "epson", "brother"]):
        return ("🖨️", "Printer")
    if any(v in vendor for v in ["sonos", "roku", "amazon", "google"]):
        return ("📺", "Smart home / media")
    if "windows" in os_name:
        return ("💻", "Windows PC")
    if "linux" in os_name:
        return ("🐧", "Linux host")
    if "mac os" in os_name or "darwin" in os_name:
        return ("💻", "Mac")
    if 80 in ports or 443 in ports or 8080 in ports:
        return ("🌐", "Web server / IoT")
    if 22 in ports:
        return ("🖥️", "Server (SSH)")
    return ("❓", "Unknown device")

def probe_http(ip: str, port: int) -> dict:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}"
    try:
        with httpx.Client(verify=False, timeout=15.0, follow_redirects=True) as c:
            r = c.get(url)
            title = ""
            if "text/html" in r.headers.get("content-type", "").lower():
                import re
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:120]
            return {
                "url": url, "status": r.status_code,
                "server": r.headers.get("server", ""),
                "title": title,
            }
    except Exception as e:
        return {"url": url, "error": str(e)[:80]}

def probe_all_web_ports(hosts: list[dict]) -> None:
    from concurrent.futures import as_completed
    web_ports = {80, 443, 8000, 8080, 8443, 8888, 5000, 3000, 9000}
    targets = []
    for host in hosts:
        for p in host["ports"]:
            if p["port"] in web_ports or "http" in p["service"]:
                targets.append((host["ip"], p))
    if not targets:
        console.print("[dim]No web ports to probe.[/dim]")
        return

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe_http, ip, p["port"]): p for ip, p in targets}
        with tqdm(total=len(futures), desc="web probes", unit="svc") as bar:
            for fut in as_completed(futures):
                p = futures[fut]
                p["http"] = fut.result()
                bar.update(1)
                bar.set_postfix_str(p["http"].get("url", "")[:40])

# ---------- LLM enrichment ----------
LLM_PROMPT = """You are a network security analyst. Given the following device information from a network scan, provide a brief security analysis.

Device info:
- IP: {ip}
- Hostname: {hostname}
- MAC: {mac}
- Vendor: {vendor}
- OS: {os}
- Open ports/services: {services}
- Web services: {web_info}

Respond in valid JSON with these keys:
- "device_type": what this device likely is (1 line)
- "default_credentials": list of known default username/password pairs for this device/vendor (e.g. [{{"user":"admin","pass":"admin"}}]). Empty list if unknown.
- "security_risks": list of short strings describing potential security risks (max 5)
- "recommendations": list of short strings with security recommendations (max 5)
- "notes": any other useful info about this device (1-2 sentences)

Only return the JSON object, no markdown fences or extra text."""

def analyze_host_with_llm(host: dict) -> dict | None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    services = []
    web_info = []
    for p in host["ports"]:
        svc = f"{p['port']}/{p['protocol']} {p['service']} {p['product']} {p['version']}".strip()
        services.append(svc)
        if "http" in p:
            h = p["http"]
            if "error" not in h:
                web_info.append(f"{h['url']} [{h['status']}] server={h.get('server','')} title={h.get('title','')}")

    prompt = LLM_PROMPT.format(
        ip=host["ip"] or "?",
        hostname=host["hostname"] or "n/a",
        mac=host["mac"] or "n/a",
        vendor=host["vendor"] or "Unknown",
        os=host["os"] or "unknown",
        services="; ".join(services) or "none",
        web_info="; ".join(web_info) or "none",
    )

    try:
        response = litellm.completion(
            model="gemini/gemini-2.5-flash",
            messages=[{"role": "user", "content": prompt}],
            api_key=api_key,
            temperature=0.2,
        )
        text = response.choices[0].message.content.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = re.sub(r"^```\w*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
        return json.loads(text)
    except Exception as e:
        console.print(f"[dim red]LLM error for {host['ip']}: {e}[/dim red]")
        return None

def enrich_hosts_with_llm(hosts: list[dict]) -> None:
    console.print("[cyan]Analyzing devices with Gemini 2.5 Flash...[/cyan]")
    with ThreadPoolExecutor(max_workers=5) as ex:
        from concurrent.futures import as_completed
        futures = {ex.submit(analyze_host_with_llm, h): h for h in hosts}
        with tqdm(total=len(futures), desc="LLM analysis", unit="host") as bar:
            for fut in as_completed(futures):
                host = futures[fut]
                result = fut.result()
                if result:
                    host["llm_analysis"] = result
                bar.update(1)

# ---------- console report ----------
def print_console_report(hosts: list[dict]) -> None:
    console.print(Panel(f"[bold green]Found {len(hosts)} live hosts[/bold green]"))
    for host in sorted(hosts, key=lambda h: tuple(int(x) for x in (h["ip"] or "0.0.0.0").split("."))):
        emoji, label = guess_device_type(host)
        header = f"[bold cyan]{host['ip']}[/bold cyan]"
        if host["hostname"]:
            header += f" ({host['hostname']})"
            if host.get("hostname_source"):
                header += f" [dim]via {host['hostname_source']}[/dim]"
        header += f"  —  {emoji} {label}"
        console.print(f"\n{header}")
        console.print(f"  MAC: {host['mac'] or 'n/a'}   Vendor: {host['vendor'] or 'n/a'}")
        console.print(f"  OS:  {host['os'] or 'unknown'}")
        if not host["ports"]:
            console.print("  [dim]No open ports[/dim]")
            continue
        table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
        table.add_column("Port"); table.add_column("Service")
        table.add_column("Product / Version"); table.add_column("Web info")
        for p in host["ports"]:
            prodver = f"{p['product']} {p['version']} {p['extrainfo']}".strip()
            web = ""
            if "http" in p:
                h = p["http"]
                if "error" in h:
                    web = f"[red]{h['error']}[/red]"
                else:
                    web = f"[{h['status']}] {h['server']}"
                    if h["title"]:
                        web += f" — {h['title']}"
            table.add_row(f"{p['port']}/{p['protocol']}", p["service"], prodver or "-", web or "-")
        console.print(table)
        if "llm_analysis" in host:
            a = host["llm_analysis"]
            console.print(f"  [bold yellow]🤖 AI Analysis:[/bold yellow] {a.get('device_type', '')}")
            if a.get("default_credentials"):
                creds = ", ".join(f"{c['user']}:{c['pass']}" for c in a["default_credentials"])
                console.print(f"  [red]⚠ Default credentials: {creds}[/red]")
            if a.get("security_risks"):
                for risk in a["security_risks"]:
                    console.print(f"  [yellow]  • {risk}[/yellow]")
            if a.get("recommendations"):
                for rec in a["recommendations"]:
                    console.print(f"  [green]  ✓ {rec}[/green]")

# ---------- severity ----------
def compute_severity(host: dict) -> tuple[str, int]:
    """Return (level, score) where higher score = more severe."""
    score = 0
    llm = host.get("llm_analysis") or {}
    if llm.get("default_credentials"):
        score += 100
    score += len(llm.get("security_risks", [])) * 10
    for p in host["ports"]:
        http = p.get("http") or {}
        if "error" not in http and 200 <= http.get("status", 0) < 400:
            if p["port"] in (80, 443, 8080, 8443, 8000, 8888):
                score += 15
    if score >= 100: return ("critical", score)
    if score >= 40:  return ("high", score)
    if score >= 15:  return ("medium", score)
    if score > 0:    return ("low", score)
    return ("info", 0)

def host_flags(host: dict) -> list[str]:
    """Filter tokens for data-flags attribute."""
    level, _ = compute_severity(host)
    flags = [level]
    llm = host.get("llm_analysis") or {}
    if llm.get("default_credentials"):
        flags.append("creds")
    if llm.get("security_risks"):
        flags.append("risks")
    if any("http" in p and "error" not in p["http"] for p in host["ports"]):
        flags.append("web")
    return flags

def build_summary(hosts: list[dict]) -> dict:
    s = {"critical": 0, "high": 0, "creds": 0, "web": 0, "risks": 0}
    for h in hosts:
        level, _ = compute_severity(h)
        if level in ("critical", "high"):
            s[level] += 1
        llm = h.get("llm_analysis") or {}
        if llm.get("default_credentials"):
            s["creds"] += 1
        if llm.get("security_risks"):
            s["risks"] += 1
        if any("http" in p and "error" not in p["http"] for p in h["ports"]):
            s["web"] += 1
    return s

# ---------- HTML report ----------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report — __TARGET__</title>
<style>
  :root {
    --bg:#0b1020; --card:#151a2e; --card2:#1c2340; --border:#2a3357;
    --text:#e6e9f5; --muted:#a7b0d3; --accent:#6ea8ff; --green:#4ade80;
    --yellow:#facc15; --red:#f87171; --orange:#fb923c;
    --mono: ui-monospace,SFMono-Regular,Menlo,monospace;
    --sev-critical:#f87171; --sev-high:#fb923c; --sev-medium:#facc15;
    --sev-low:#4ade80; --sev-info:#6ea8ff;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,sans-serif;
    background:linear-gradient(180deg,#0b1020,#0e1430); color:var(--text); min-height:100vh; }
  header { padding:32px 40px; border-bottom:1px solid var(--border);
    background:rgba(255,255,255,0.02); backdrop-filter:blur(10px); }
  h1 { margin:0 0 8px; font-size:28px; }
  .meta { color:var(--muted); font-size:14px; }
  .stats { display:flex; gap:12px; margin-top:20px; flex-wrap:wrap; }
  .stat { background:var(--card); border:1px solid var(--border); border-radius:12px;
    padding:14px 18px; min-width:120px; }
  .stat .v { font-size:22px; font-weight:700; color:var(--accent); }
  .stat .l { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; }
  .stat.alert .v { color:var(--red); }
  .stat.warn  .v { color:var(--orange); }
  .stat.note  .v { color:var(--yellow); }

  .controls { padding:20px 40px 0; display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
  input[type=search] { flex:1; min-width:240px; background:var(--card); border:1px solid var(--border);
    color:var(--text); padding:10px 16px; border-radius:10px; font-size:14px; }
  input[type=search]:focus { outline:2px solid var(--accent); outline-offset:1px; border-color:var(--accent); }

  .view-toggle { display:flex; background:var(--card); border:1px solid var(--border);
    border-radius:10px; overflow:hidden; }
  .view-btn { background:transparent; border:0; color:var(--muted); padding:9px 14px;
    font-size:13px; cursor:pointer; transition:all .15s; font-family:inherit; }
  .view-btn:hover { color:var(--text); }
  .view-btn.active { background:var(--accent); color:#0b1020; font-weight:600; }

  .chips { display:flex; gap:8px; flex-wrap:wrap; padding:12px 40px 0; }
  .chip { background:var(--card); border:1px solid var(--border); color:var(--muted);
    padding:6px 12px; border-radius:999px; font-size:12px; cursor:pointer;
    transition:all .15s; user-select:none; }
  .chip:hover { color:var(--text); border-color:var(--accent); }
  .chip.active { background:var(--accent); color:#0b1020; border-color:var(--accent); font-weight:600; }
  .chip .count { opacity:.75; margin-left:4px; font-weight:500; }

  main { padding:20px 40px 60px; }
  #hosts { display:grid; grid-template-columns:repeat(auto-fill,minmax(420px,1fr)); gap:20px; }
  #hosts.hidden, #hosts-list.hidden { display:none; }

  .host { background:var(--card); border:1px solid var(--border); border-radius:14px;
    overflow:hidden; transition:transform .15s,border-color .15s; border-left-width:4px; }
  .host:hover { transform:translateY(-2px); border-color:var(--accent); }
  .host.sev-critical { border-left-color:var(--sev-critical); }
  .host.sev-high     { border-left-color:var(--sev-high); }
  .host.sev-medium   { border-left-color:var(--sev-medium); }
  .host.sev-low      { border-left-color:var(--sev-low); }
  .host.sev-info     { border-left-color:var(--sev-info); }

  .host-head { padding:16px 20px; border-bottom:1px solid var(--border); background:var(--card2); }
  .host-head .top { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .host-head .ip { font-size:20px; font-weight:700; font-family:var(--mono); color:var(--accent); }
  .host-head .hn { color:var(--muted); font-size:13px; }
  .hn-src { display:inline-block; background:rgba(110,168,255,0.12); color:var(--accent);
    font-size:10px; font-weight:600; padding:1px 6px; border-radius:4px;
    text-transform:uppercase; letter-spacing:0.3px; margin-left:4px; vertical-align:middle; }
  .host-head .type { margin-top:6px; font-size:14px; }
  .host-head .det { margin-top:10px; font-size:12px; color:var(--muted); line-height:1.6; }
  .host-head .det b { color:var(--text); font-weight:500; }

  .sev-pill { display:inline-block; padding:2px 8px; border-radius:6px; font-size:10px;
    font-weight:700; text-transform:uppercase; letter-spacing:0.5px; }
  .sev-pill.sev-critical { background:rgba(248,113,113,0.18); color:var(--sev-critical); }
  .sev-pill.sev-high     { background:rgba(251,146,60,0.18); color:var(--sev-high); }
  .sev-pill.sev-medium   { background:rgba(250,204,21,0.18); color:var(--sev-medium); }
  .sev-pill.sev-low      { background:rgba(74,222,128,0.18); color:var(--sev-low); }
  .sev-pill.sev-info     { background:rgba(110,168,255,0.18); color:var(--sev-info); }

  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { padding:10px 12px; text-align:left; border-bottom:1px solid var(--border); }
  th { background:rgba(255,255,255,0.02); font-size:11px; text-transform:uppercase;
    color:var(--muted); letter-spacing:0.5px; font-weight:600; }
  td.port { font-family:var(--mono); color:var(--accent); font-weight:600; }
  td.service { font-family:var(--mono); }
  a.port-link { color:var(--accent); }
  a.port-link:hover { text-decoration:underline; }
  a.port-link .ext { font-size:10px; opacity:0.7; vertical-align:1px; }
  .badge { display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:600; }
  .badge.ok   { background:rgba(74,222,128,0.15); color:var(--green); }
  .badge.warn { background:rgba(250,204,21,0.15); color:var(--yellow); }
  .badge.err  { background:rgba(248,113,113,0.15); color:var(--red); }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .empty { padding:20px; color:var(--muted); font-style:italic; text-align:center; }
  .web-title { display:block; color:var(--muted); font-size:11px; margin-top:2px; }

  .llm-analysis { padding:16px 20px; border-top:1px solid var(--border); background:rgba(110,168,255,0.03); }
  .llm-title { font-size:14px; font-weight:700; margin-bottom:8px; color:var(--accent); }
  .llm-device { font-size:13px; margin-bottom:10px; color:var(--text); }
  .llm-section { font-size:12px; margin-bottom:10px; }
  .llm-section b { color:var(--text); }
  .llm-section ul { margin:4px 0 0 16px; padding:0; }
  .llm-section li { margin:3px 0; line-height:1.5; }
  .llm-section.risks li::marker { color:var(--yellow); }
  .llm-section.recs  li::marker { color:var(--green); }
  .llm-notes { font-size:12px; color:var(--muted); font-style:italic; margin-top:6px; }

  .creds-box { background:rgba(248,113,113,0.12); border:1px solid rgba(248,113,113,0.35);
    border-radius:8px; padding:10px 12px; margin-bottom:10px; }
  .creds-box .title { font-size:12px; font-weight:700; color:var(--red); margin-bottom:6px;
    display:flex; align-items:center; gap:6px; }
  .cred-item { display:flex; align-items:center; gap:8px; margin:4px 0; }
  .cred-item code { background:rgba(0,0,0,0.35); color:var(--text); padding:2px 8px;
    border-radius:4px; font-family:var(--mono); font-size:12px; }
  .copy-btn { background:transparent; border:1px solid var(--border); color:var(--muted);
    padding:2px 8px; border-radius:4px; font-size:11px; cursor:pointer; transition:all .15s;
    font-family:inherit; }
  .copy-btn:hover { color:var(--text); border-color:var(--accent); }

  #empty-state { padding:60px 20px; text-align:center; color:var(--muted); font-size:14px; display:none; }
  #empty-state h3 { color:var(--text); margin:0 0 8px; font-size:18px; }

  .host-list { background:var(--card); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  .host-list th { padding:12px; }
  .host-list td { padding:12px; vertical-align:middle; }
  .host-list tr.host-row { transition:background .15s; }
  .host-list tr.host-row:hover { background:rgba(110,168,255,0.05); }
  .host-list tr.host-row td:first-child { border-left:3px solid transparent; }
  .host-list tr.host-row.sev-critical td:first-child { border-left-color:var(--sev-critical); }
  .host-list tr.host-row.sev-high     td:first-child { border-left-color:var(--sev-high); }
  .host-list tr.host-row.sev-medium   td:first-child { border-left-color:var(--sev-medium); }
  .host-list tr.host-row.sev-low      td:first-child { border-left-color:var(--sev-low); }
  .host-list tr.host-row.sev-info     td:first-child { border-left-color:var(--sev-info); }
  .host-list .ip-cell { font-family:var(--mono); color:var(--accent); font-weight:600; }
  .host-list .muted { color:var(--muted); font-size:12px; }
  .flag-tag { display:inline-block; padding:1px 6px; border-radius:4px; font-size:10px;
    font-weight:600; margin-right:4px; }
  .flag-tag.creds { background:rgba(248,113,113,0.18); color:var(--red); }
  .flag-tag.web   { background:rgba(110,168,255,0.18); color:var(--accent); }
  .flag-tag.risks { background:rgba(250,204,21,0.18); color:var(--yellow); }

  #top-btn { position:fixed; bottom:24px; right:24px; width:44px; height:44px;
    background:var(--accent); color:#0b1020; border:0; border-radius:50%;
    font-size:20px; font-weight:700; cursor:pointer; display:none;
    box-shadow:0 4px 12px rgba(0,0,0,0.35); }
  #top-btn:hover { filter:brightness(1.1); }

  @media (max-width: 640px) {
    header, .controls, .chips, main { padding-left:16px; padding-right:16px; }
    #hosts { grid-template-columns:1fr; }
  }
</style>
</head>
<body>
<header>
  <h1>🛰️ Network Scan Report</h1>
  <div class="meta">Target: <b>__TARGET__</b> &nbsp;•&nbsp; Scanned: __TS__</div>
  <div class="stats">
    <div class="stat"><div class="v">__N_HOSTS__</div><div class="l">Live Hosts</div></div>
    <div class="stat"><div class="v">__N_PORTS__</div><div class="l">Open Ports</div></div>
    <div class="stat alert"><div class="v">__N_CRITICAL__</div><div class="l">Critical</div></div>
    <div class="stat alert"><div class="v">__N_CREDS__</div><div class="l">Default Creds</div></div>
    <div class="stat warn"><div class="v">__N_WEB__</div><div class="l">Exposed Web</div></div>
    <div class="stat note"><div class="v">__N_RISKS__</div><div class="l">With Risks</div></div>
  </div>
</header>
<div class="controls">
  <input type="search" id="search" placeholder="🔍 Filter by IP, hostname, vendor, service...">
  <div class="view-toggle" role="tablist" aria-label="View mode">
    <button class="view-btn active" data-view="cards" aria-pressed="true">▦ Cards</button>
    <button class="view-btn" data-view="list" aria-pressed="false">☰ List</button>
  </div>
</div>
<div class="chips" role="group" aria-label="Filter hosts">
  <div class="chip active" data-filter="all" tabindex="0">All</div>
  <div class="chip" data-filter="critical" tabindex="0">Critical</div>
  <div class="chip" data-filter="high" tabindex="0">High</div>
  <div class="chip" data-filter="creds" tabindex="0">Default Creds</div>
  <div class="chip" data-filter="web" tabindex="0">Web Exposed</div>
  <div class="chip" data-filter="risks" tabindex="0">With Risks</div>
</div>
<main>
  <div id="hosts">
__CARDS__
  </div>
  <div id="hosts-list" class="hidden">
    <table class="host-list">
      <thead>
        <tr><th>Severity</th><th>IP</th><th>Device</th><th>OS</th><th>Open Ports</th><th>Flags</th></tr>
      </thead>
      <tbody>
__ROWS__
      </tbody>
    </table>
  </div>
  <div id="empty-state">
    <h3>No matching hosts</h3>
    <div>Try a different filter or clear the search.</div>
  </div>
</main>
<button id="top-btn" title="Back to top" aria-label="Back to top">↑</button>
<script>
  const search = document.getElementById('search');
  const hostCards = document.querySelectorAll('.host');
  const hostRows = document.querySelectorAll('.host-row');
  const chips = document.querySelectorAll('.chip');
  const viewBtns = document.querySelectorAll('.view-btn');
  const hostsEl = document.getElementById('hosts');
  const listEl = document.getElementById('hosts-list');
  const emptyEl = document.getElementById('empty-state');
  const topBtn = document.getElementById('top-btn');
  let activeFilter = 'all';
  let currentView = 'cards';

  function matches(el) {
    const q = search.value.toLowerCase();
    const text = el.textContent.toLowerCase();
    const flags = (el.dataset.flags || '').split(' ');
    return text.includes(q) && (activeFilter === 'all' || flags.includes(activeFilter));
  }

  function applyFilters() {
    let visible = 0;
    hostCards.forEach(el => {
      const s = matches(el);
      el.style.display = s ? '' : 'none';
      if (s && currentView === 'cards') visible++;
    });
    hostRows.forEach(el => {
      const s = matches(el);
      el.style.display = s ? '' : 'none';
      if (s && currentView === 'list') visible++;
    });
    emptyEl.style.display = visible === 0 ? '' : 'none';
  }

  function applyView() {
    hostsEl.classList.toggle('hidden', currentView !== 'cards');
    listEl.classList.toggle('hidden', currentView !== 'list');
    applyFilters();
  }

  search.addEventListener('input', applyFilters);
  chips.forEach(c => c.addEventListener('click', () => {
    chips.forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    activeFilter = c.dataset.filter;
    applyFilters();
  }));
  viewBtns.forEach(b => b.addEventListener('click', () => {
    viewBtns.forEach(x => { x.classList.remove('active'); x.setAttribute('aria-pressed', 'false'); });
    b.classList.add('active');
    b.setAttribute('aria-pressed', 'true');
    currentView = b.dataset.view;
    applyView();
  }));
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    navigator.clipboard.writeText(btn.dataset.value).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ copied';
      setTimeout(() => { btn.textContent = orig; }, 1200);
    });
  });
  window.addEventListener('scroll', () => {
    topBtn.style.display = window.scrollY > 400 ? 'block' : 'none';
  });
  topBtn.addEventListener('click', () => window.scrollTo({top:0,behavior:'smooth'}));
</script>
</body>
</html>
"""

WEB_PORTS_HTTP = {80, 631, 3000, 5000, 8000, 8080, 8888, 9000}
WEB_PORTS_HTTPS = {443, 8443}

def web_url_for(ip: str, port_info: dict) -> str | None:
    """Return a browser URL for a web-ish port, else None."""
    if not ip:
        return None
    port = port_info.get("port")
    service = (port_info.get("service") or "").lower()
    if port in WEB_PORTS_HTTPS or "https" in service or "ssl/http" in service:
        return f"https://{ip}:{port}"
    if port in WEB_PORTS_HTTP or "http" in service:
        return f"http://{ip}:{port}"
    return None


def render_host_card(host: dict) -> str:
    level, _ = compute_severity(host)
    emoji, label = guess_device_type(host)
    ip = html.escape(host["ip"] or "?")
    hn = ""
    if host["hostname"]:
        src = host.get("hostname_source")
        src_tag = f' <span class="hn-src" title="Source">{html.escape(src)}</span>' if src else ""
        hn = f'<span class="hn">({html.escape(host["hostname"])})</span>{src_tag}'
    mac = html.escape(host["mac"] or "n/a")
    vendor = html.escape(host["vendor"] or "Unknown")
    os_name = html.escape(host["os"] or "unknown")
    flags_attr = html.escape(" ".join(host_flags(host)))
    sev_pill = f'<span class="sev-pill sev-{level}">{level}</span>'

    if not host["ports"]:
        body = '<div class="empty">No open ports</div>'
    else:
        rows = []
        for p in host["ports"]:
            prodver = html.escape(f"{p['product']} {p['version']} {p['extrainfo']}".strip() or "-")
            web_cell = "-"
            if "http" in p:
                h = p["http"]
                if "error" in h:
                    web_cell = f'<span class="badge err">{html.escape(h["error"])}</span>'
                else:
                    status = h["status"]
                    cls = "ok" if status < 400 else "warn" if status < 500 else "err"
                    server = html.escape(h.get("server", "") or "")
                    title = html.escape(h.get("title", "") or "")
                    web_cell = (
                        f'<a href="{html.escape(h["url"])}" target="_blank" rel="noopener noreferrer">'
                        f'<span class="badge {cls}">{status}</span> {server}</a>'
                    )
                    if title:
                        web_cell += f'<span class="web-title">{title}</span>'
            port_label = f'{p["port"]}/{p["protocol"]}'
            url = web_url_for(host["ip"] or "", p)
            if url:
                port_cell = (
                    f'<td class="port"><a href="{html.escape(url)}" target="_blank" '
                    f'rel="noopener noreferrer" title="Open {html.escape(url)} in new tab" '
                    f'class="port-link">{port_label} <span class="ext">↗</span></a></td>'
                )
            else:
                port_cell = f'<td class="port">{port_label}</td>'
            rows.append(
                f'<tr>{port_cell}'
                f'<td class="service">{html.escape(p["service"])}</td>'
                f'<td>{prodver}</td><td>{web_cell}</td></tr>'
            )
        body = (
            '<table><thead><tr><th>Port</th><th>Service</th>'
            '<th>Product / Version</th><th>Web</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )

    llm_html = ""
    if "llm_analysis" in host:
        a = host["llm_analysis"]
        llm_html = '<div class="llm-analysis">'
        llm_html += '<div class="llm-title">🤖 AI Analysis</div>'
        llm_html += f'<div class="llm-device">{html.escape(a.get("device_type", ""))}</div>'
        if a.get("default_credentials"):
            llm_html += '<div class="creds-box">'
            llm_html += '<div class="title">⚠ Default Credentials</div>'
            for c in a["default_credentials"]:
                u = html.escape(c.get("user", "") or "")
                pw = html.escape(c.get("pass", "") or "")
                val = f"{u}:{pw}"
                llm_html += (
                    f'<div class="cred-item"><code>{val}</code>'
                    f'<button class="copy-btn" data-value="{val}">📋 copy</button></div>'
                )
            llm_html += '</div>'
        if a.get("security_risks"):
            llm_html += '<div class="llm-section risks"><b>⚠ Security Risks:</b><ul>'
            for r in a["security_risks"]:
                llm_html += f'<li>{html.escape(r)}</li>'
            llm_html += '</ul></div>'
        if a.get("recommendations"):
            llm_html += '<div class="llm-section recs"><b>✓ Recommendations:</b><ul>'
            for r in a["recommendations"]:
                llm_html += f'<li>{html.escape(r)}</li>'
            llm_html += '</ul></div>'
        if a.get("notes"):
            llm_html += f'<div class="llm-notes">{html.escape(a["notes"])}</div>'
        llm_html += '</div>'

    return f"""
<div class="host sev-{level}" data-flags="{flags_attr}">
  <div class="host-head">
    <div class="top">
      <span class="ip">{ip}</span>{hn} {sev_pill}
    </div>
    <div class="type">{emoji} {html.escape(label)}</div>
    <div class="det">
      <b>MAC:</b> {mac} &nbsp; <b>Vendor:</b> {vendor}<br>
      <b>OS:</b> {os_name}
    </div>
  </div>
  {body}
  {llm_html}
</div>
"""

def render_host_row(host: dict) -> str:
    level, _ = compute_severity(host)
    emoji, label = guess_device_type(host)
    ip = html.escape(host["ip"] or "?")
    if host["hostname"]:
        src = host.get("hostname_source")
        src_tag = f' <span class="hn-src">{html.escape(src)}</span>' if src else ""
        hn_html = f' <span class="muted">({html.escape(host["hostname"])})</span>{src_tag}'
    else:
        hn_html = ""
    os_name = html.escape(host["os"] or "unknown")
    flags = host_flags(host)
    flags_attr = html.escape(" ".join(flags))

    ports = host["ports"]
    if ports:
        items = []
        for p in ports[:6]:
            url = web_url_for(host["ip"] or "", p)
            port_label = str(p["port"])
            if url:
                items.append(
                    f'<a href="{html.escape(url)}" target="_blank" '
                    f'rel="noopener noreferrer" class="port-link" '
                    f'title="Open {html.escape(url)}">{port_label} ↗</a>'
                )
            else:
                items.append(port_label)
        shown = ", ".join(items)
        if len(ports) > 6:
            shown += f', <span class="muted">+{len(ports) - 6}</span>'
        port_summary = f'{len(ports)} <span class="muted">({shown})</span>'
    else:
        port_summary = '<span class="muted">none</span>'

    flag_tags = ""
    if "creds" in flags:
        flag_tags += '<span class="flag-tag creds">creds</span>'
    if "web" in flags:
        flag_tags += '<span class="flag-tag web">web</span>'
    if "risks" in flags:
        flag_tags += '<span class="flag-tag risks">risks</span>'
    if not flag_tags:
        flag_tags = '<span class="muted">—</span>'

    return (
        f'<tr class="host-row sev-{level}" data-flags="{flags_attr}">'
        f'<td><span class="sev-pill sev-{level}">{level}</span></td>'
        f'<td class="ip-cell">{ip}{hn_html}</td>'
        f'<td>{emoji} {html.escape(label)}</td>'
        f'<td class="muted">{os_name}</td>'
        f'<td>{port_summary}</td>'
        f'<td>{flag_tags}</td>'
        f'</tr>'
    )

def write_html_report(hosts: list[dict], target: str, out_file: str | None = None) -> None:
    if out_file is None:
        subnet_part = target.replace("/", "_").replace(".", "-")
        date_part = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = f"scan_report_{subnet_part}_{date_part}.html"

    def sort_key(h):
        _, score = compute_severity(h)
        ip = h.get("ip") or "255.255.255.255"
        try:
            ip_tuple = tuple(int(x) for x in ip.split("."))
        except ValueError:
            ip_tuple = (255, 255, 255, 255)
        return (-score, ip_tuple)

    sorted_hosts = sorted(hosts, key=sort_key)
    cards = "\n".join(render_host_card(h) for h in sorted_hosts)
    rows = "\n".join(render_host_row(h) for h in sorted_hosts)
    summary = build_summary(hosts)
    n_ports = sum(len(h["ports"]) for h in hosts)
    ts = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    replacements = {
        "__TARGET__": html.escape(target),
        "__TS__": html.escape(ts),
        "__N_HOSTS__": str(len(hosts)),
        "__N_PORTS__": str(n_ports),
        "__N_CRITICAL__": str(summary["critical"]),
        "__N_CREDS__": str(summary["creds"]),
        "__N_WEB__": str(summary["web"]),
        "__N_RISKS__": str(summary["risks"]),
        "__CARDS__": cards,
        "__ROWS__": rows,
    }
    html_out = HTML_TEMPLATE
    for k, v in replacements.items():
        html_out = html_out.replace(k, v)
    with open(out_file, "w") as f:
        f.write(html_out)
    console.print(f"[green]HTML report saved to {out_file}[/green]")

# ---------- list subnets ----------
def list_subnets() -> None:
    """Detect and display all network interfaces with their subnets."""
    console.print(Panel("[bold green]Available Network Interfaces & Subnets[/bold green]"))
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Interface")
    table.add_column("IP Address")
    table.add_column("Netmask")
    table.add_column("Subnet (CIDR)")
    table.add_column("Status")

    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["ipconfig", "/all"], text=True, errors="replace")
            _parse_ipconfig(out, table)
        else:
            out = subprocess.check_output(["ifconfig"], text=True, errors="replace")
            _parse_ifconfig(out, table)
    except FileNotFoundError:
        console.print("[red]Could not run ifconfig/ipconfig. Make sure it is installed.[/red]")
        sys.exit(1)

    console.print(table)
    console.print("\n[dim]Use any Subnet (CIDR) value above as the target, e.g.:[/dim]")
    console.print("[cyan]  sudo python3 netscan-py.py 192.168.1.0/24[/cyan]")


def _parse_ifconfig(output: str, table: Table) -> None:
    """Parse ifconfig output (macOS / Linux)."""
    iface_re = re.compile(r"^(\S+?):\s+flags=\d+<([^>]*)>", re.MULTILINE)
    inet_re = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)")

    blocks = re.split(r"(?=^\S+:\s+flags=)", output, flags=re.MULTILINE)
    for block in blocks:
        iface_m = iface_re.search(block)
        if not iface_m:
            continue
        iface_name = iface_m.group(1)
        flags = iface_m.group(2)
        is_up = "UP" in flags
        is_loopback = "LOOPBACK" in flags

        for inet_m in inet_re.finditer(block):
            ip_str = inet_m.group(1)
            mask_str = inet_m.group(2)
            if mask_str.startswith("0x"):
                mask_int = int(mask_str, 16)
                mask_str = f"{(mask_int >> 24) & 0xff}.{(mask_int >> 16) & 0xff}.{(mask_int >> 8) & 0xff}.{mask_int & 0xff}"
            try:
                iface = ipaddress.IPv4Interface(f"{ip_str}/{mask_str}")
                subnet = str(iface.network)
            except ValueError:
                subnet = "?"

            status = "[green]active[/green]" if is_up and not is_loopback else (
                "[dim]loopback[/dim]" if is_loopback else "[dim]inactive[/dim]"
            )
            table.add_row(iface_name, ip_str, mask_str, subnet, status)


def _parse_ipconfig(output: str, table: Table) -> None:
    """Parse ipconfig /all output (Windows)."""
    iface_name = ""
    for line in output.splitlines():
        # Section headers for adapters
        adapter_m = re.match(r"^(\S.*adapter\s+.+?):\s*$", line, re.I)
        if adapter_m:
            iface_name = adapter_m.group(1)
            continue
        ip_m = re.match(r"\s+IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if ip_m:
            ip_str = ip_m.group(1)
            continue
        mask_m = re.match(r"\s+Subnet Mask[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if mask_m and ip_str:
            mask_str = mask_m.group(1)
            try:
                iface = ipaddress.IPv4Interface(f"{ip_str}/{mask_str}")
                subnet = str(iface.network)
            except ValueError:
                subnet = "?"
            table.add_row(iface_name, ip_str, mask_str, subnet, "[green]active[/green]")
            ip_str = ""


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(
        description="Network scanner with AI-powered device analysis.",
    )
    parser.add_argument("target", nargs="?", help="Target subnet to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--list-subnets", "-l", action="store_true",
                        help="List all available network interfaces and subnets")
    parser.add_argument("--ai", action=argparse.BooleanOptionalAction, default=None,
                        help="Enable/disable AI device analysis. "
                             "Default: auto-enabled when GEMINI_API_KEY is set.")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("--fast", action="store_true",
                            help="Fast scan: top 100 ports only (quicker but misses non-standard services)")
    port_group.add_argument("--all-ports", action="store_true",
                            help="Scan all 65535 ports per host (very slow)")
    parser.add_argument("--no-ping", action="store_true",
                        help="Skip host discovery; treat every IP as alive. "
                             "Slower but catches hosts that block all ping probes.")
    args = parser.parse_args()

    if args.list_subnets:
        list_subnets()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    has_key = bool(os.environ.get("GEMINI_API_KEY"))
    if args.ai is False:
        ai_enabled, ai_reason = False, "disabled via --no-ai"
    elif args.ai is True and not has_key:
        ai_enabled, ai_reason = False, "--ai requested but GEMINI_API_KEY is not set"
    elif has_key:
        ai_enabled, ai_reason = True, "Gemini 2.5 Flash"
    else:
        ai_enabled, ai_reason = False, "GEMINI_API_KEY not set (pass --ai to force, or set it in .env)"
    state = "[green]ENABLED[/green]" if ai_enabled else "[yellow]DISABLED[/yellow]"
    console.print(f"[bold]🤖 AI analysis:[/bold] {state} — {ai_reason}")

    target = args.target
    port_mode = "fast" if args.fast else "all" if args.all_ports else "common"
    xml_file = run_nmap(target, port_mode=port_mode, skip_ping=args.no_ping)
    hosts = parse_nmap_xml(xml_file)
    enrich_hostnames(hosts)
    console.print("[cyan]Probing web ports...[/cyan]")
    probe_all_web_ports(hosts)
    if ai_enabled:
        enrich_hosts_with_llm(hosts)
    print_console_report(hosts)
    with open("scan_results.json", "w") as f:
        json.dump(hosts, f, indent=2, default=str)
    subnet_part = target.replace("/", "_").replace(".", "-")
    date_part = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"scan_report_{subnet_part}_{date_part}.html"
    write_html_report(hosts, target, report_file)
    console.print(f"[green]Done. Open {report_file} in your browser.[/green]")

if __name__ == "__main__":
    main()