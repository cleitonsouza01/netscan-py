#!/usr/bin/env python3
"""
Network scanner: wraps nmap, probes HTTP services, outputs console + HTML report.
Usage: sudo python3 netscan.py 192.168.1.0/24
"""
import os
import re
from tqdm import tqdm
import subprocess
import sys
import json
import html
import datetime
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
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
def run_nmap(target: str, xml_out: str = "scan.xml") -> str:
    console.print(f"[cyan]Running nmap on {target}...[/cyan]")
    console.print("[dim]A /24 scan with service + OS detection takes 3–10 minutes.[/dim]")
    cmd = [
        "nmap", "-sS", "-sV", "-O", "-F", "--open",
        "-T4", "-v", "--stats-every", "3s",
        "-oX", xml_out, target,
    ]
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
        ip = mac = vendor = hostname = os_name = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor", "Unknown")
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
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
            "ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor,
            "os": os_name, "ports": ports,
        })
    return hosts

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
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        console.print("[yellow]GEMINI_API_KEY not set in .env — skipping LLM analysis.[/yellow]")
        return

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

# ---------- HTML report ----------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report — {target}</title>
<style>
  :root {{
    --bg:#0b1020; --card:#151a2e; --card2:#1c2340; --border:#2a3357;
    --text:#e6e9f5; --muted:#8b93b5; --accent:#6ea8ff; --green:#4ade80;
    --yellow:#facc15; --red:#f87171; --mono: ui-monospace,SFMono-Regular,Menlo,monospace;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:-apple-system,Segoe UI,Roboto,sans-serif;
    background:linear-gradient(180deg,#0b1020,#0e1430); color:var(--text); min-height:100vh; }}
  header {{ padding:32px 40px; border-bottom:1px solid var(--border);
    background:rgba(255,255,255,0.02); backdrop-filter:blur(10px); }}
  h1 {{ margin:0 0 8px; font-size:28px; }}
  .meta {{ color:var(--muted); font-size:14px; }}
  .stats {{ display:flex; gap:16px; margin-top:20px; flex-wrap:wrap; }}
  .stat {{ background:var(--card); border:1px solid var(--border); border-radius:12px;
    padding:16px 20px; min-width:120px; }}
  .stat .v {{ font-size:24px; font-weight:700; color:var(--accent); }}
  .stat .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; }}
  .controls {{ padding:24px 40px 0; display:flex; gap:12px; flex-wrap:wrap; }}
  input[type=search] {{ flex:1; min-width:240px; background:var(--card); border:1px solid var(--border);
    color:var(--text); padding:12px 16px; border-radius:10px; font-size:14px; }}
  input[type=search]:focus {{ outline:none; border-color:var(--accent); }}
  main {{ padding:24px 40px 60px; display:grid; grid-template-columns:repeat(auto-fill,minmax(460px,1fr)); gap:20px; }}
  .host {{ background:var(--card); border:1px solid var(--border); border-radius:14px;
    overflow:hidden; transition:transform .15s,border-color .15s; }}
  .host:hover {{ transform:translateY(-2px); border-color:var(--accent); }}
  .host-head {{ padding:18px 20px; border-bottom:1px solid var(--border); background:var(--card2); }}
  .host-head .ip {{ font-size:20px; font-weight:700; font-family:var(--mono); color:var(--accent); }}
  .host-head .hn {{ color:var(--muted); font-size:13px; margin-left:8px; }}
  .host-head .type {{ margin-top:6px; font-size:14px; }}
  .host-head .det {{ margin-top:10px; font-size:12px; color:var(--muted); line-height:1.6; }}
  .host-head .det b {{ color:var(--text); font-weight:500; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ padding:10px 12px; text-align:left; border-bottom:1px solid var(--border); }}
  th {{ background:rgba(255,255,255,0.02); font-size:11px; text-transform:uppercase;
    color:var(--muted); letter-spacing:0.5px; font-weight:600; }}
  td.port {{ font-family:var(--mono); color:var(--accent); font-weight:600; }}
  td.service {{ font-family:var(--mono); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:600; }}
  .badge.ok {{ background:rgba(74,222,128,0.15); color:var(--green); }}
  .badge.warn {{ background:rgba(250,204,21,0.15); color:var(--yellow); }}
  .badge.err {{ background:rgba(248,113,113,0.15); color:var(--red); }}
  a {{ color:var(--accent); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .empty {{ padding:20px; color:var(--muted); font-style:italic; text-align:center; }}
  .web-title {{ display:block; color:var(--muted); font-size:11px; margin-top:2px; }}
  .llm-analysis {{ padding:16px 20px; border-top:1px solid var(--border); background:rgba(110,168,255,0.03); }}
  .llm-title {{ font-size:14px; font-weight:700; margin-bottom:8px; color:var(--accent); }}
  .llm-device {{ font-size:13px; margin-bottom:10px; color:var(--text); }}
  .llm-section {{ font-size:12px; margin-bottom:8px; }}
  .llm-section b {{ color:var(--text); }}
  .llm-section ul {{ margin:4px 0 0 16px; padding:0; }}
  .llm-section li {{ margin:2px 0; line-height:1.5; }}
  .llm-section.creds {{ color:var(--red); }}
  .llm-section.creds code {{ background:rgba(248,113,113,0.15); padding:1px 6px; border-radius:4px; font-family:var(--mono); font-size:12px; }}
  .llm-section.risks {{ color:var(--yellow); }}
  .llm-section.recs {{ color:var(--green); }}
  .llm-notes {{ font-size:12px; color:var(--muted); font-style:italic; margin-top:6px; }}
</style>
</head>
<body>
<header>
  <h1>🛰️ Network Scan Report</h1>
  <div class="meta">Target: <b>{target}</b> &nbsp;•&nbsp; Scanned: {ts}</div>
  <div class="stats">
    <div class="stat"><div class="v">{n_hosts}</div><div class="l">Live Hosts</div></div>
    <div class="stat"><div class="v">{n_ports}</div><div class="l">Open Ports</div></div>
    <div class="stat"><div class="v">{n_web}</div><div class="l">Web Services</div></div>
  </div>
</header>
<div class="controls">
  <input type="search" id="search" placeholder="🔍 Filter by IP, hostname, vendor, service...">
</div>
<main id="hosts">
{cards}
</main>
<script>
  const search = document.getElementById('search');
  const hosts = document.querySelectorAll('.host');
  search.addEventListener('input', e => {{
    const q = e.target.value.toLowerCase();
    hosts.forEach(h => {{
      h.style.display = h.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
  }});
</script>
</body>
</html>
"""

def render_host_card(host: dict) -> str:
    emoji, label = guess_device_type(host)
    ip = html.escape(host["ip"] or "?")
    hn = f'<span class="hn">{html.escape(host["hostname"])}</span>' if host["hostname"] else ""
    mac = html.escape(host["mac"] or "n/a")
    vendor = html.escape(host["vendor"] or "Unknown")
    os_name = html.escape(host["os"] or "unknown")

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
                        f'<a href="{html.escape(h["url"])}" target="_blank">'
                        f'<span class="badge {cls}">{status}</span> {server}</a>'
                    )
                    if title:
                        web_cell += f'<span class="web-title">{title}</span>'
            rows.append(
                f'<tr><td class="port">{p["port"]}/{p["protocol"]}</td>'
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
        llm_html += f'<div class="llm-title">🤖 AI Analysis</div>'
        llm_html += f'<div class="llm-device">{html.escape(a.get("device_type", ""))}</div>'
        if a.get("default_credentials"):
            llm_html += '<div class="llm-section creds"><b>⚠ Default Credentials:</b><ul>'
            for c in a["default_credentials"]:
                llm_html += f'<li><code>{html.escape(c["user"])}:{html.escape(c["pass"])}</code></li>'
            llm_html += '</ul></div>'
        if a.get("security_risks"):
            llm_html += '<div class="llm-section risks"><b>Security Risks:</b><ul>'
            for r in a["security_risks"]:
                llm_html += f'<li>{html.escape(r)}</li>'
            llm_html += '</ul></div>'
        if a.get("recommendations"):
            llm_html += '<div class="llm-section recs"><b>Recommendations:</b><ul>'
            for r in a["recommendations"]:
                llm_html += f'<li>{html.escape(r)}</li>'
            llm_html += '</ul></div>'
        if a.get("notes"):
            llm_html += f'<div class="llm-notes">{html.escape(a["notes"])}</div>'
        llm_html += '</div>'

    return f"""
<div class="host">
  <div class="host-head">
    <div><span class="ip">{ip}</span>{hn}</div>
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

def write_html_report(hosts: list[dict], target: str, out_file: str | None = None) -> None:
    if out_file is None:
        subnet_part = target.replace("/", "_").replace(".", "-")
        date_part = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = f"scan_report_{subnet_part}_{date_part}.html"
    sorted_hosts = sorted(hosts, key=lambda h: tuple(int(x) for x in (h["ip"] or "0.0.0.0").split(".")))
    cards = "\n".join(render_host_card(h) for h in sorted_hosts)
    n_ports = sum(len(h["ports"]) for h in hosts)
    n_web = sum(1 for h in hosts for p in h["ports"] if "http" in p and "error" not in p["http"])
    html_out = HTML_TEMPLATE.format(
        target=html.escape(target),
        ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        n_hosts=len(hosts), n_ports=n_ports, n_web=n_web,
        cards=cards,
    )
    with open(out_file, "w") as f:
        f.write(html_out)
    console.print(f"[green]HTML report saved to {out_file}[/green]")

# ---------- main ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 netscan.py 192.168.1.0/24")
        sys.exit(1)
    target = sys.argv[1]
    xml_file = run_nmap(target)
    hosts = parse_nmap_xml(xml_file)
    console.print("[cyan]Probing web ports...[/cyan]")
    probe_all_web_ports(hosts)
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