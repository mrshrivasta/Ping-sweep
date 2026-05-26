"""
╔══════════════════════════════════════════════════════════════════╗
║     PING SWEEP / HOST DISCOVERY TOOL v2.0 — FULL REWRITE       ║
║     Made by Karanam Shrivasta                                    ║
║     LinkedIn : https://www.linkedin.com/in/karanam-shrivasta/   ║
║     GitHub   : https://github.com/mrshrivasta                   ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠  LEGAL DISCLAIMER                                            ║
║  Educational / research use ONLY on networks you OWN or have    ║
║  EXPLICIT WRITTEN PERMISSION to scan.                           ║
║  May violate CFAA (US) · CMA 1990 (UK) · IT Act 2000 (India)   ║
║  Author assumes ZERO LIABILITY for misuse.                      ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python ping_sweep.py                  # CLI scan
  python ping_sweep.py --web            # 5-page web UI → http://localhost:5000
  python ping_sweep.py --help           # all options

Requirements:
  pip install flask
"""

import os, re, sys, csv, json, time, socket, struct, platform
import subprocess, argparse, ipaddress, threading
import concurrent.futures
from datetime import datetime

# ── Optional scapy ────────────────────────────────────────────────────────────
try:
    import scapy.all as scapy
    SCAPY = True
except ImportError:
    SCAPY = False

# ── Constants ─────────────────────────────────────────────────────────────────
PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 1433:"MSSQL", 3306:"MySQL",
    3389:"RDP", 5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt",
    8443:"HTTPS-Alt", 27017:"MongoDB",
}

COMMON_PORTS   = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080,8443]
DEFAULT_PORTS  = [22,80,443,3389,8080]

OS_SIGNATURES = [
    (range(0,   65),  "Linux / macOS",         "🐧"),
    (range(65,  129), "Windows",                "🪟"),
    (range(129, 256), "Cisco / Network Device", "🔌"),
]

ROUTER_PORTS  = {53, 80, 443, 8080, 23}
PRINTER_PORTS = {9100, 631, 515}
WINDOWS_PORTS = {135, 139, 445, 3389}
LINUX_PORTS   = {22, 111}

# ── Subnet auto-detection ─────────────────────────────────────────────────────
def get_local_subnets() -> list[str]:
    """Detect all local /24 subnets from active interfaces."""
    subnets = []
    os_name = platform.system()
    try:
        if os_name == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"IPv4.*?:\s*([\d.]+)", line)
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127."):
                        parts = ip.rsplit(".", 1)
                        if len(parts) == 2:
                            subnets.append(parts[0])
        else:
            out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
            for m in re.finditer(r"inet\s+([\d.]+)/(\d+)", out):
                ip, prefix = m.group(1), int(m.group(2))
                if not ip.startswith("127.") and prefix >= 16:
                    parts = ip.rsplit(".", 1)
                    if len(parts) == 2:
                        subnets.append(parts[0])
    except Exception:
        pass
    # fallback
    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            subnets.append(ip.rsplit(".", 1)[0])
        except Exception:
            subnets.append("192.168.1")
    return list(dict.fromkeys(subnets))  # deduplicate

# ── ICMP ping — cross-platform, robust ───────────────────────────────────────
def icmp_ping(ip: str, timeout: float = 1.5) -> dict | None:
    """
    Reliable cross-platform ping.
    Parses RTT and TTL from subprocess output on Windows, Linux, macOS.
    Returns {'rtt': float, 'ttl': int} or None.
    """
    os_name = platform.system()
    t_ms    = str(int(timeout * 1000))

    if os_name == "Windows":
        cmd = ["ping", "-n", "1", "-w", t_ms, ip]
    elif os_name == "Darwin":
        cmd = ["ping", "-c", "1", "-W", t_ms, "-t", "64", ip]
    else:                              # Linux
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 3, errors="replace"
        )
        out = proc.stdout + proc.stderr

        if proc.returncode != 0:
            return None

        # ── RTT parsing ───────────────────────────────────────────────────────
        rtt = None
        # Windows: "Average = 14ms" or "time=14ms" or "time<1ms"
        for pat in [
            r"[Aa]verage\s*=\s*([\d.]+)\s*ms",
            r"[Mm]in.*?[Aa]vg.*?[Mm]ax.*?=\s*[\d.]+/\s*([\d.]+)",
            r"time[=<]([\d.]+)\s*ms",
            r"time\s*=\s*([\d.]+)\s*ms",
            r"rtt.*?=\s*[\d.]+/([\d.]+)",
        ]:
            m = re.search(pat, out)
            if m:
                try:
                    rtt = round(float(m.group(1)), 2)
                    break
                except ValueError:
                    pass
        # Windows "time<1ms" → 0.5
        if rtt is None and re.search(r"time<1ms", out, re.IGNORECASE):
            rtt = 0.5

        # ── TTL parsing ───────────────────────────────────────────────────────
        ttl = None
        for pat in [r"TTL=(\d+)", r"ttl=(\d+)", r"TTL (\d+)"]:
            m = re.search(pat, out, re.IGNORECASE)
            if m:
                try:
                    ttl = int(m.group(1))
                    break
                except ValueError:
                    pass

        # Must have at least one of rtt/ttl to confirm host is up
        if rtt is None and ttl is None:
            return None

        return {"rtt": rtt, "ttl": ttl}

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


# ── TCP connect scan ──────────────────────────────────────────────────────────
def tcp_connect(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Full TCP connect — no root needed."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def tcp_fallback_ping(ip: str, ports=(80, 443, 22, 3389, 8080), timeout=0.8) -> bool:
    """
    TCP-based host detection: if ANY common port is open → host is up.
    Used as fallback when ICMP is blocked by firewall.
    """
    for port in ports:
        if tcp_connect(ip, port, timeout):
            return True
    return False


# ── Port scanner ──────────────────────────────────────────────────────────────
def scan_ports(ip: str, ports: list[int], timeout: float = 0.8) -> dict:
    """Scan multiple ports concurrently."""
    results = {}

    def check(port):
        open_ = tcp_connect(ip, port, timeout)
        results[port] = {
            "state":   "open" if open_ else "closed",
            "service": PORT_SERVICES.get(port, "unknown"),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), 20)) as ex:
        ex.map(check, ports)

    return results


# ── Reverse DNS ───────────────────────────────────────────────────────────────
def reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


# ── OS detection ─────────────────────────────────────────────────────────────
def detect_os(ttl: int | None, open_ports: set[int]) -> dict:
    """
    Multi-factor OS detection: TTL + open port fingerprinting.
    Returns {'os': str, 'confidence': str, 'icon': str}
    """
    os_guess    = "Unknown"
    confidence  = "low"
    icon        = "❓"

    # TTL-based detection
    ttl_guess = None
    if ttl:
        for rng, name, ic in OS_SIGNATURES:
            if ttl in rng:
                ttl_guess = name
                icon = ic
                break

    # Port-based refinement
    port_guess = None
    if open_ports & WINDOWS_PORTS:
        port_guess = "Windows"
        icon = "🪟"
    elif open_ports & LINUX_PORTS:
        port_guess = "Linux / macOS"
        icon = "🐧"
    elif open_ports & PRINTER_PORTS:
        port_guess = "Network Printer"
        icon = "🖨️"
    elif open_ports & ROUTER_PORTS == ROUTER_PORTS & open_ports and len(open_ports & ROUTER_PORTS) >= 2:
        port_guess = "Router / Gateway"
        icon = "📡"

    # Merge
    if ttl_guess and port_guess:
        if ttl_guess.startswith(port_guess[:5]) or port_guess.startswith(ttl_guess[:5]):
            os_guess   = port_guess
            confidence = "high"
        else:
            os_guess   = f"{port_guess} (TTL:{ttl})"
            confidence = "medium"
    elif port_guess:
        os_guess   = port_guess
        confidence = "medium"
    elif ttl_guess:
        os_guess   = ttl_guess
        confidence = "medium"

    return {"os": os_guess, "confidence": confidence, "icon": icon}


# ── Device type detection ────────────────────────────────────────────────────
def detect_device_type(open_ports: set[int], hostname: str | None, os_name: str) -> str:
    if open_ports & PRINTER_PORTS:
        return "Printer"
    if 23 in open_ports and (53 in open_ports or 80 in open_ports):
        return "Router / Switch"
    if open_ports & WINDOWS_PORTS:
        return "Windows PC / Server"
    if 22 in open_ports and open_ports & LINUX_PORTS:
        return "Linux Server"
    if hostname and any(k in hostname.lower() for k in ["router","gateway","modem","ap","switch"]):
        return "Network Device"
    if hostname and any(k in hostname.lower() for k in ["print","printer","hp","canon","epson"]):
        return "Printer"
    if 5900 in open_ports:
        return "Remote Desktop (VNC)"
    if 27017 in open_ports or 3306 in open_ports:
        return "Database Server"
    return "Unknown device"


# ── Full host scan ────────────────────────────────────────────────────────────
def scan_host(
    ip: str,
    ports: list[int] = None,
    timeout: float = 1.5,
    do_dns: bool = True,
) -> dict:
    """
    Complete host scan:
      1. ICMP ping (with RTT + TTL parsing)
      2. TCP fallback if ICMP blocked
      3. Port scanning
      4. Reverse DNS
      5. OS + device type fingerprinting
    """
    if ports is None:
        ports = DEFAULT_PORTS

    result = {
        "ip":          ip,
        "status":      "down",
        "rtt":         None,
        "ttl":         None,
        "os":          None,
        "os_icon":     "❓",
        "os_conf":     "low",
        "device_type": None,
        "hostname":    None,
        "ports":       {},
        "open_ports":  [],
        "method":      None,
        "scanned_at":  datetime.now().isoformat(timespec="seconds"),
    }

    # ── Step 1: ICMP ─────────────────────────────────────────────────────────
    ping = icmp_ping(ip, timeout=timeout)

    if ping:
        result["status"] = "up"
        result["rtt"]    = ping["rtt"]
        result["ttl"]    = ping["ttl"]
        result["method"] = "ICMP"
    else:
        # ── Step 2: TCP fallback ──────────────────────────────────────────────
        tcp_up = tcp_fallback_ping(ip, ports=ports, timeout=timeout * 0.6)
        if tcp_up:
            result["status"] = "up"
            result["method"] = "TCP-fallback"

    if result["status"] == "down":
        return result

    # ── Step 3: Port scan ─────────────────────────────────────────────────────
    result["ports"] = scan_ports(ip, ports, timeout=min(timeout * 0.8, 1.0))
    result["open_ports"] = [
        p for p, info in result["ports"].items() if info["state"] == "open"
    ]

    # ── Step 4: Reverse DNS ───────────────────────────────────────────────────
    if do_dns:
        result["hostname"] = reverse_dns(ip, timeout=timeout)

    # ── Step 5: OS + device fingerprinting ────────────────────────────────────
    open_set = set(result["open_ports"])
    os_info  = detect_os(result["ttl"], open_set)
    result["os"]       = os_info["os"]
    result["os_icon"]  = os_info["icon"]
    result["os_conf"]  = os_info["confidence"]
    result["device_type"] = detect_device_type(
        open_set, result["hostname"], result["os"]
    )

    return result


# ── Subnet sweep ──────────────────────────────────────────────────────────────
def ping_sweep(
    subnet_base: str,
    start: int = 1,
    end:   int = 254,
    ports: list[int] = None,
    workers: int = 60,
    timeout: float = 1.5,
    on_result=None,
) -> list[dict]:
    if ports is None:
        ports = DEFAULT_PORTS

    targets = [f"{subnet_base}.{i}" for i in range(start, end + 1)]
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_host, ip, ports, timeout, True): ip for ip in targets}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            results.append(res)
            if on_result:
                on_result(res)

    results.sort(key=lambda r: int(r["ip"].split(".")[-1]))
    return results


# ── Output helpers ────────────────────────────────────────────────────────────
def print_results(results: list[dict]):
    up = [r for r in results if r["status"] == "up"]
    print(f"\n{'═'*72}")
    print(f"  Ping Sweep Results  —  {len(up)}/{len(results)} hosts up")
    print(f"  Made by Karanam Shrivasta | github.com/mrshrivasta")
    print(f"{'═'*72}")
    hdr = "  {:<18} {:<8} {:<7} {:<5} {:<25} {}"
    print(hdr.format("IP", "Status", "RTT", "TTL", "OS", "Hostname"))
    print("  " + "─"*68)
    for r in results:
        if r["status"] == "up":
            rtt  = f"{r['rtt']}ms" if r["rtt"] is not None else "—"
            ttl  = str(r["ttl"]) if r["ttl"] else "—"
            os_  = (r.get("os") or "—")[:25]
            host = r.get("hostname") or "—"
            print(hdr.format(r["ip"], "UP", rtt, ttl, os_, host))
            if r["open_ports"]:
                for p in r["open_ports"]:
                    svc = PORT_SERVICES.get(p, "?")
                    print(f"    ✓ {p}/{svc}")
    print(f"{'═'*72}\n")


def save_csv(results, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip","status","rtt_ms","ttl","os","device_type","hostname","open_ports","method","scanned_at"])
        for r in results:
            w.writerow([
                r["ip"], r["status"], r.get("rtt") or "",
                r.get("ttl") or "", r.get("os") or "",
                r.get("device_type") or "", r.get("hostname") or "",
                ";".join(str(p) for p in r.get("open_ports",[])),
                r.get("method") or "", r.get("scanned_at",""),
            ])
    print(f"  [CSV] → {path}")


def save_json(results, path):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  [JSON] → {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def cli_mode():
    parser = argparse.ArgumentParser(
        description="Ping Sweep v2 — Karanam Shrivasta | github.com/mrshrivasta",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ping_sweep.py
  python ping_sweep.py --subnet 192.168.0 --start 1 --end 254
  python ping_sweep.py --ports 22,80,443,3389 --workers 80 --csv out.csv
  python ping_sweep.py --web
        """,
    )
    parser.add_argument("--web",     action="store_true")
    parser.add_argument("--subnet",  default=None,         help="Subnet base e.g. 192.168.1 (auto-detect if omitted)")
    parser.add_argument("--start",   type=int, default=1)
    parser.add_argument("--end",     type=int, default=50)
    parser.add_argument("--ports",   default="22,80,443,3389,8080")
    parser.add_argument("--workers", type=int, default=60)
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--csv",     default=None)
    parser.add_argument("--json",    default=None)
    parser.add_argument("--all-ports", action="store_true", help="Scan all common ports")
    args = parser.parse_args()

    if args.web:
        web_mode(); return

    subnet = args.subnet
    if not subnet:
        detected = get_local_subnets()
        subnet   = detected[0] if detected else "192.168.1"
        print(f"  Auto-detected subnet: {subnet}.x")

    ports = list(dict.fromkeys(
        COMMON_PORTS if args.all_ports
        else [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    ))

    print(f"\n{'═'*60}")
    print(f"  Ping Sweep / Host Discovery v2.0")
    print(f"  Subnet  : {subnet}.{args.start} — {subnet}.{args.end}")
    print(f"  Ports   : {ports}")
    print(f"  Workers : {args.workers}  |  Timeout: {args.timeout}s")
    print(f"  OS      : {platform.system()}")
    print(f"  Scapy   : {'available' if SCAPY else 'not installed'}")
    print(f"  Made by Karanam Shrivasta  ⚠ Authorised networks only")
    print(f"{'═'*60}\n")

    lock = threading.Lock()
    count = [0]

    def on_result(r):
        with lock:
            count[0] += 1
            sym = "[UP  ]" if r["status"] == "up" else "[----]"
            rtt = f"{r['rtt']}ms" if r.get("rtt") is not None else "     "
            method = r.get("method") or ""
            print(f"  {sym} {r['ip']:<18} {rtt:<9} {method}")

    results = ping_sweep(
        subnet, args.start, args.end,
        ports=ports, workers=args.workers,
        timeout=args.timeout, on_result=on_result,
    )

    print_results(results)
    if args.csv:  save_csv(results, args.csv)
    if args.json: save_json(results, args.json)


# ═══════════════════════════════════════════════════════════════════════════════
# FLASK 5-PAGE WEB APP
# ═══════════════════════════════════════════════════════════════════════════════

BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} | Ping Sweep — Karanam Shrivasta</title>
<meta name="description" content="Educational ping sweep and host discovery tool. {title}. Built by Karanam Shrivasta.">
<meta name="keywords" content="ping sweep, host discovery, network scanner, port scan, OS fingerprint, ethical hacking education, Karanam Shrivasta">
<meta name="author" content="Karanam Shrivasta">
<meta name="robots" content="index,follow">
<meta name="geo.region" content="IN">
<meta property="og:title" content="{title} | Ping Sweep Tool">
<meta property="og:type" content="website">
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Ping Sweep Tool",
"author":{{"@type":"Person","name":"Karanam Shrivasta","url":"https://www.linkedin.com/in/karanam-shrivasta/",
"sameAs":["https://github.com/mrshrivasta"]}},"applicationCategory":"SecurityApplication",
"offers":{{"@type":"Offer","price":"0"}}}}
</script>
<style>
:root{{--blue:#1A6FD4;--green:#1D9E75;--purple:#534AB7;--red:#E24B4A;--amber:#EF9F27;
      --bg:#f0f2f5;--card:#fff;--bdr:#e2e8f0;--text:#1a202c;--muted:#64748b;--mono:'Courier New',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
/* Sidebar */
.sidebar{{position:fixed;top:0;left:0;width:220px;height:100vh;background:#1e293b;
          padding:1.5rem 0;display:flex;flex-direction:column;z-index:100}}
.sidebar-logo{{padding:0 1.25rem 1.5rem;border-bottom:1px solid #334155}}
.sidebar-logo .logo-title{{font-size:16px;font-weight:700;color:#f1f5f9}}
.sidebar-logo .logo-sub{{font-size:11px;color:#64748b;margin-top:2px}}
.nav-links{{padding:.75rem 0;flex:1}}
.nav-link{{display:flex;align-items:center;gap:10px;padding:10px 1.25rem;
           font-size:13px;color:#94a3b8;text-decoration:none;transition:all .15s;border-left:3px solid transparent}}
.nav-link:hover{{color:#f1f5f9;background:#334155}}
.nav-link.active{{color:#60a5fa;background:#1e3a5f;border-left-color:#3b82f6}}
.nav-link .icon{{font-size:16px;width:18px;text-align:center}}
.sidebar-foot{{padding:1rem 1.25rem;border-top:1px solid #334155}}
.sidebar-foot a{{display:block;font-size:11px;color:#64748b;text-decoration:none;margin-bottom:4px}}
.sidebar-foot a:hover{{color:#94a3b8}}
.sidebar-foot .made-by{{font-size:11px;color:#475569;margin-bottom:8px}}
/* Main */
.main{{margin-left:220px;padding:2rem;min-height:100vh}}
.page-header{{margin-bottom:1.5rem}}
.page-header h1{{font-size:22px;font-weight:700;margin-bottom:4px}}
.page-header p{{font-size:13px;color:var(--muted)}}
/* Cards */
.card{{background:var(--card);border-radius:12px;border:1px solid var(--bdr);padding:1.25rem;margin-bottom:1rem}}
.card-title{{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;
             letter-spacing:.5px;margin-bottom:.875rem}}
/* Disclaimer */
.disc{{background:#FCEBEB;border:1px solid #F09595;border-radius:10px;
       padding:.875rem 1.25rem;margin-bottom:1rem}}
.disc-title{{font-size:13px;font-weight:700;color:#791F1F;margin-bottom:4px}}
.disc-body{{font-size:12px;color:#A32D2D;line-height:1.7}}
/* Tabs */
.tabs{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:.875rem}}
.tab{{padding:6px 14px;border-radius:50px;border:1px solid var(--bdr);font-size:12px;
      cursor:pointer;background:white;color:var(--muted);transition:all .15s;user-select:none}}
.tab:hover{{background:#f8fafc}}
.tab.active{{background:var(--blue);color:white;border-color:var(--blue)}}
/* Form */
.form-row{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:.875rem}}
.form-row label{{font-size:13px;color:var(--muted);white-space:nowrap}}
input,select{{border:1px solid var(--bdr);border-radius:8px;padding:8px 12px;
              font-size:13px;font-family:var(--mono);background:white;color:var(--text)}}
input:focus,select:focus{{outline:2px solid var(--blue);border-color:transparent}}
/* Buttons */
.btn{{padding:9px 20px;border-radius:50px;border:none;font-size:13px;font-weight:600;
      cursor:pointer;transition:opacity .15s;display:inline-flex;align-items:center;gap:6px}}
.btn:hover{{opacity:.85}}
.btn-blue{{background:var(--blue);color:white}}
.btn-red{{background:var(--red);color:white}}
.btn-green{{background:var(--green);color:white}}
.btn-gray{{background:#f1f5f9;color:var(--text);border:1px solid var(--bdr)}}
.btn-purple{{background:var(--purple);color:white}}
/* Stats */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:1rem}}
.stat{{background:#f8fafc;border-radius:10px;padding:12px;border:1px solid var(--bdr)}}
.stat-v{{font-size:24px;font-weight:700}}
.stat-l{{font-size:11px;color:var(--muted);margin-top:2px}}
/* Progress */
.bar-wrap{{height:6px;background:#e2e8f0;border-radius:3px;margin-bottom:.875rem;overflow:hidden}}
.bar{{height:6px;border-radius:3px;background:var(--blue);width:0%;transition:width .25s}}
/* Host map */
.host-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(56px,1fr));gap:5px;margin-bottom:.875rem}}
.hc{{border-radius:8px;padding:6px 3px;font-size:11px;font-family:var(--mono);text-align:center;
     border:1px solid var(--bdr);cursor:pointer;transition:all .15s;color:var(--muted);background:#f8fafc}}
.hc.up{{background:#DCFCE7;color:#166534;border-color:#86efac;font-weight:700}}
.hc.scanning{{background:#DBEAFE;color:#1e40af;border-color:#93c5fd;animation:pulse 1s infinite}}
.hc.sel{{outline:2px solid var(--blue);outline-offset:2px}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
/* Detail */
.detail-tbl{{width:100%;font-size:13px;border-collapse:collapse}}
.detail-tbl tr{{border-bottom:1px solid var(--bdr)}}
.detail-tbl tr:last-child{{border:none}}
.detail-tbl td{{padding:7px 6px}}
.detail-tbl td:first-child{{color:var(--muted);width:150px;font-size:12px}}
.detail-tbl td:last-child{{font-family:var(--mono);font-weight:600}}
/* Port tags */
.port-tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;
           font-family:var(--mono);margin:2px}}
.open{{background:#DCFCE7;color:#166534}}
.closed{{background:#FEE2E2;color:#991B1B}}
/* Log */
.log-box{{background:#0f172a;border-radius:10px;padding:1rem;font-family:var(--mono);
          font-size:11px;max-height:200px;overflow-y:auto;line-height:1.9;color:#64748b}}
.ok{{color:#4ade80}}.warn{{color:#fbbf24}}.err{{color:#f87171}}.info{{color:#60a5fa}}
/* Legend */
.legend{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:.875rem}}
.leg{{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)}}
.dot{{width:10px;height:10px;border-radius:2px;flex-shrink:0}}
/* Table */
.results-table{{width:100%;font-size:13px;border-collapse:collapse}}
.results-table th{{background:#f8fafc;padding:9px 10px;text-align:left;font-size:11px;
                   font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;
                   border-bottom:1px solid var(--bdr)}}
.results-table td{{padding:9px 10px;border-bottom:1px solid #f1f5f9;vertical-align:middle}}
.results-table tr:hover td{{background:#f8fafc}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.badge-up{{background:#DCFCE7;color:#166534}}
.badge-down{{background:#F1F5F9;color:#64748b}}
/* Watermark */
.watermark{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
            border-top:1px solid var(--bdr);padding-top:1rem;margin-top:1rem}}
.wm-name{{font-size:13px;font-weight:700}}
.wm-role{{font-size:11px;color:var(--muted)}}
.wm-links a{{font-size:12px;color:var(--blue);text-decoration:none;margin-left:10px;font-weight:500}}
/* Responsive */
@media(max-width:768px){{
  .sidebar{{width:100%;height:auto;position:relative;flex-direction:row;flex-wrap:wrap}}
  .main{{margin-left:0;padding:1rem}}
}}
</style>
</head>
<body>
<nav class="sidebar" role="navigation" aria-label="Main navigation">
  <div class="sidebar-logo">
    <div class="logo-title">🔍 Ping Sweep</div>
    <div class="logo-sub">Host Discovery Tool v2</div>
  </div>
  <div class="nav-links">
    <a href="/" class="nav-link {a_scan}"><span class="icon">🎯</span> Scanner</a>
    <a href="/results" class="nav-link {a_results}"><span class="icon">📋</span> Results</a>
    <a href="/ports" class="nav-link {a_ports}"><span class="icon">🔌</span> Port Scanner</a>
    <a href="/osdetect" class="nav-link {a_os}"><span class="icon">💻</span> OS Detection</a>
    <a href="/about" class="nav-link {a_about}"><span class="icon">ℹ️</span> About / Help</a>
  </div>
  <div class="sidebar-foot">
    <div class="made-by">Made by Karanam Shrivasta</div>
    <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank" rel="noopener">LinkedIn ↗</a>
    <a href="https://github.com/mrshrivasta" target="_blank" rel="noopener">GitHub ↗</a>
  </div>
</nav>
<main class="main" role="main">
{content}
</main>
</body>
</html>
"""

# ── Shared scan state ──────────────────────────────────────────────────────────
_scan_state = {
    "running":  False,
    "results":  {},
    "total":    0,
    "done":     0,
    "up":       0,
    "queue":    [],      # SSE event queue
    "lock":     threading.Lock(),
}


def page(content: str, active: str = "scan", title: str = "Scanner") -> str:
    active_map = {k: "" for k in ["scan","results","ports","os","about"]}
    active_map[active] = "active"
    return BASE_HTML.format(
        title=title,
        content=content,
        a_scan=active_map["scan"],
        a_results=active_map["results"],
        a_ports=active_map["ports"],
        a_os=active_map["os"],
        a_about=active_map["about"],
    )


# ── Page 1: Scanner ───────────────────────────────────────────────────────────
PAGE_SCAN = """
<div class="page-header">
  <h1>🎯 Network Scanner</h1>
  <p>Discover live hosts on your subnet with ICMP + TCP fallback scanning</p>
</div>

<div class="disc" role="alert">
  <div class="disc-title">⚠️ Legal disclaimer — read before use</div>
  <div class="disc-body">Use <strong>only</strong> on networks you own or have <strong>explicit written permission</strong> to scan. Unauthorised scanning may violate <strong>CFAA</strong> (US) · <strong>Computer Misuse Act 1990</strong> (UK) · <strong>IT Act 2000</strong> (India). <strong>Karanam Shrivasta</strong> assumes zero liability for misuse.</div>
</div>

<div class="card">
  <div class="card-title">Target configuration</div>
  <div class="form-row">
    <label>Subnet base</label>
    <input id="subnet" value="" placeholder="auto-detect" style="width:160px">
    <span style="font-size:13px;color:var(--muted)">.  Start</span>
    <input type="number" id="s-start" value="1" min="1" max="254" style="width:65px">
    <span style="font-size:13px;color:var(--muted)">End</span>
    <input type="number" id="s-end" value="50" min="1" max="254" style="width:65px">
    <button class="btn btn-gray" id="auto-btn" style="font-size:12px;padding:7px 14px">Auto-detect</button>
  </div>
  <div class="card-title">Ports to check</div>
  <div class="tabs" id="port-tabs">
    <div class="tab active" data-p="22">22 SSH</div>
    <div class="tab active" data-p="80">80 HTTP</div>
    <div class="tab active" data-p="443">443 HTTPS</div>
    <div class="tab" data-p="3389">3389 RDP</div>
    <div class="tab" data-p="21">21 FTP</div>
    <div class="tab" data-p="23">23 Telnet</div>
    <div class="tab" data-p="445">445 SMB</div>
    <div class="tab" data-p="8080">8080 Alt-HTTP</div>
    <div class="tab" data-p="3306">3306 MySQL</div>
    <div class="tab" data-p="5900">5900 VNC</div>
  </div>
  <div class="card-title">Scan speed</div>
  <div class="form-row">
    <span style="font-size:12px;color:var(--muted)">Slow</span>
    <input type="range" id="workers" min="1" max="5" value="3" step="1" style="width:200px">
    <span style="font-size:12px;color:var(--muted)">Fast</span>
    <span id="workers-lbl" style="font-size:13px;font-weight:600;min-width:80px">50 threads</span>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn btn-blue" id="start-btn">▶ Start scan</button>
    <button class="btn btn-red" id="stop-btn" style="display:none">⏸ Stop</button>
    <button class="btn btn-gray" id="clear-btn">✕ Clear</button>
  </div>
</div>

<div class="card">
  <div class="card-title">Progress</div>
  <div class="stats-grid">
    <div class="stat"><div class="stat-v" id="st-total">0</div><div class="stat-l">targets</div></div>
    <div class="stat"><div class="stat-v" id="st-up" style="color:var(--green)">0</div><div class="stat-l">hosts up</div></div>
    <div class="stat"><div class="stat-v" id="st-down" style="color:#94a3b8">0</div><div class="stat-l">no response</div></div>
    <div class="stat"><div class="stat-v" id="st-pct">0%</div><div class="stat-l">complete</div></div>
    <div class="stat"><div class="stat-v" id="st-time">0s</div><div class="stat-l">elapsed</div></div>
  </div>
  <div class="bar-wrap"><div class="bar" id="prog-bar"></div></div>
  <div id="scan-status" style="font-size:12px;color:var(--muted);margin-bottom:.875rem">Ready to scan</div>

  <div class="legend">
    <div class="leg"><div class="dot" style="background:#86efac"></div>Host up</div>
    <div class="leg"><div class="dot" style="background:#e2e8f0"></div>No response</div>
    <div class="leg"><div class="dot" style="background:#93c5fd"></div>Scanning</div>
  </div>
  <div class="host-grid" id="host-grid"></div>
</div>

<div class="card" id="detail-panel" style="display:none">
  <div class="card-title">Host detail — <span id="detail-ip" style="color:var(--blue)"></span></div>
  <table class="detail-tbl">
    <tr><td>Status</td><td id="d-status">—</td></tr>
    <tr><td>Response time</td><td id="d-rtt">—</td></tr>
    <tr><td>TTL</td><td id="d-ttl">—</td></tr>
    <tr><td>Detection method</td><td id="d-method">—</td></tr>
    <tr><td>OS guess</td><td id="d-os">—</td></tr>
    <tr><td>OS confidence</td><td id="d-conf">—</td></tr>
    <tr><td>Device type</td><td id="d-dev">—</td></tr>
    <tr><td>Hostname (rDNS)</td><td id="d-host">—</td></tr>
  </table>
  <div style="font-size:12px;color:var(--muted);margin:.75rem 0 6px;font-weight:600">Ports</div>
  <div id="d-ports"></div>
</div>

<div class="card">
  <div class="card-title">Activity log</div>
  <div class="log-box" id="log"></div>
  <div style="display:flex;gap:8px;margin-top:.75rem;flex-wrap:wrap">
    <button class="btn btn-gray" onclick="exportCSV()" style="font-size:12px;padding:7px 14px">⬇ CSV</button>
    <button class="btn btn-gray" onclick="exportJSON()" style="font-size:12px;padding:7px 14px">⬇ JSON</button>
    <button class="btn btn-gray" onclick="copyLog()" style="font-size:12px;padding:7px 14px">⎘ Copy log</button>
    <button class="btn btn-purple" onclick="location.href='/results'" style="font-size:12px;padding:7px 14px">📋 Full results table</button>
  </div>
</div>

<div class="watermark">
  <div><div class="wm-name">Made by Karanam Shrivasta</div>
  <div class="wm-role">Network Security Educator · Ethical Hacking Researcher · Open Source Developer</div></div>
  <div class="wm-links">
    <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank" rel="noopener">LinkedIn</a>
    <a href="https://github.com/mrshrivasta" target="_blank" rel="noopener">GitHub</a>
  </div>
</div>

<script>
const WMAP=[10,25,50,75,100];
let selPorts=new Set(['22','80','443']);
let scan={results:{},total:0,done:0,running:false,es:null,startTime:null,timer:null};

document.getElementById('workers').addEventListener('input',function(){
  document.getElementById('workers-lbl').textContent=WMAP[this.value-1]+' threads';
});

document.querySelectorAll('#port-tabs .tab').forEach(t=>{
  if(t.classList.contains('active'))selPorts.add(t.dataset.p);
  t.addEventListener('click',function(){
    this.classList.toggle('active');
    selPorts[this.classList.contains('active')?'add':'delete'](this.dataset.p);
  });
});

document.getElementById('auto-btn').addEventListener('click',async()=>{
  const r=await fetch('/api/subnets');
  const d=await r.json();
  if(d.subnets&&d.subnets.length){
    document.getElementById('subnet').value=d.subnets[0];
    addLog('Auto-detected subnet: '+d.subnets[0],'ok');
  }
});

function ts(){return new Date().toLocaleTimeString();}
function addLog(msg,type='info'){
  const el=document.getElementById('log');
  el.innerHTML+=`<span class="${type}">[${ts()}]</span> ${msg}\\n`;
  el.scrollTop=el.scrollHeight;
}

function updateStats(){
  const vals=Object.values(scan.results);
  const up=vals.filter(v=>v.status==='up').length;
  document.getElementById('st-total').textContent=scan.total;
  document.getElementById('st-up').textContent=up;
  document.getElementById('st-down').textContent=vals.filter(v=>v.status==='down').length;
  document.getElementById('st-pct').textContent=scan.total?Math.round(scan.done/scan.total*100)+'%':'0%';
  document.getElementById('prog-bar').style.width=scan.total?(scan.done/scan.total*100)+'%':'0%';
}

function showDetail(ip){
  const r=scan.results[ip];if(!r||r.status==='pending')return;
  document.querySelectorAll('.hc').forEach(x=>x.classList.remove('sel'));
  const c=document.getElementById('c-'+ip);if(c)c.classList.add('sel');
  document.getElementById('detail-panel').style.display='block';
  document.getElementById('detail-ip').textContent=ip;
  document.getElementById('d-status').textContent=r.status==='up'?'✅ Online':'❌ No response';
  document.getElementById('d-rtt').textContent=r.rtt!=null?r.rtt+'ms':'—';
  document.getElementById('d-ttl').textContent=r.ttl||'—';
  document.getElementById('d-method').textContent=r.method||'—';
  document.getElementById('d-os').textContent=(r.os_icon||'')+(r.os||'—');
  document.getElementById('d-conf').textContent=r.os_conf||'—';
  document.getElementById('d-dev').textContent=r.device_type||'—';
  document.getElementById('d-host').textContent=r.hostname||'—';
  const pe=document.getElementById('d-ports');
  if(r.ports&&Object.keys(r.ports).length){
    pe.innerHTML=Object.entries(r.ports).map(([p,i])=>
      `<span class="port-tag ${i.state}">${p}/${i.service}[${i.state}]</span>`).join('');
  } else {
    pe.innerHTML='<span style="font-size:12px;color:var(--muted)">No port data</span>';
  }
}

function buildGrid(){
  const subnet=document.getElementById('subnet').value.trim()||'192.168.1';
  const s=parseInt(document.getElementById('s-start').value);
  const e=parseInt(document.getElementById('s-end').value);
  const grid=document.getElementById('host-grid');
  grid.innerHTML='';scan.results={};scan.total=e-s+1;scan.done=0;
  for(let i=s;i<=e;i++){
    const ip=subnet+'.'+i;
    const c=document.createElement('div');
    c.className='hc';c.id='c-'+ip;c.textContent='.'+i;c.title=ip;
    c.addEventListener('click',()=>showDetail(ip));
    grid.appendChild(c);
  }
  updateStats();
}

function startScan(){
  buildGrid();
  const subnet=document.getElementById('subnet').value.trim()||'192.168.1';
  const s=parseInt(document.getElementById('s-start').value);
  const e=parseInt(document.getElementById('s-end').value);
  const workers=WMAP[document.getElementById('workers').value-1];
  const ports=[...selPorts].join(',');
  scan.running=true;scan.startTime=Date.now();
  document.getElementById('start-btn').style.display='none';
  document.getElementById('stop-btn').style.display='inline-flex';
  document.getElementById('scan-status').textContent='Scanning '+subnet+'.'+s+'–'+e+'...';
  addLog('Scan started: '+subnet+'.'+s+'-'+e+' | ports:'+ports+' | workers:'+workers,'info');
  scan.timer=setInterval(()=>{
    document.getElementById('st-time').textContent=Math.round((Date.now()-scan.startTime)/1000)+'s';
  },1000);
  if(scan.es)scan.es.close();
  scan.es=new EventSource('/api/scan?subnet='+encodeURIComponent(subnet)+'&start='+s+'&end='+e+'&ports='+ports+'&workers='+workers);
  scan.es.addEventListener('result',ev=>{
    const r=JSON.parse(ev.data);
    scan.results[r.ip]=r;scan.done++;
    const c=document.getElementById('c-'+r.ip);
    if(c){
      if(r.status==='up'){
        c.className='hc up';c.title=r.ip+(r.rtt!=null?' ('+r.rtt+'ms)':'');
        addLog('UP: '+r.ip+(r.rtt!=null?' | '+r.rtt+'ms':'')+(r.ttl?' | TTL:'+r.ttl:'')+' | '+r.os+' | '+r.method,'ok');
      } else {
        c.className='hc';
      }
    }
    updateStats();
  });
  scan.es.addEventListener('done',ev=>{
    const d=JSON.parse(ev.data);
    finishScan(d.up,d.total);
  });
  scan.es.onerror=()=>{finishScan(Object.values(scan.results).filter(r=>r.status==='up').length,scan.total);};
}

function finishScan(up,total){
  if(scan.es)scan.es.close();
  if(scan.timer)clearInterval(scan.timer);
  scan.running=false;
  document.getElementById('start-btn').style.display='inline-flex';
  document.getElementById('stop-btn').style.display='none';
  document.getElementById('scan-status').textContent='Scan complete — '+up+'/'+total+' hosts up';
  addLog('Scan complete. '+up+'/'+total+' hosts responded.','ok');
  updateStats();
}

function stopScan(){
  if(scan.es)scan.es.close();
  if(scan.timer)clearInterval(scan.timer);
  scan.running=false;
  document.getElementById('start-btn').style.display='inline-flex';
  document.getElementById('stop-btn').style.display='none';
  document.getElementById('scan-status').textContent='Stopped by user.';
  addLog('Scan stopped.','warn');
}

function clearAll(){
  stopScan();
  document.getElementById('host-grid').innerHTML='';
  document.getElementById('log').innerHTML='';
  document.getElementById('detail-panel').style.display='none';
  scan={results:{},total:0,done:0,running:false,es:null,startTime:null,timer:null};
  document.getElementById('scan-status').textContent='Ready to scan';
  document.getElementById('st-time').textContent='0s';
  addLog('Cleared.','info');updateStats();
}

function exportCSV(){
  const rows=['IP,Status,RTT(ms),TTL,OS,DeviceType,Hostname,OpenPorts,Method'];
  Object.values(scan.results).filter(r=>r.status).forEach(r=>{
    const op=(r.open_ports||[]).join(';');
    rows.push([r.ip,r.status,r.rtt!=null?r.rtt:'',r.ttl||'',r.os||'',r.device_type||'',r.hostname||'',op,r.method||''].join(','));
  });
  dl(rows.join('\\n'),'scan_results.csv','text/csv');
  addLog('CSV exported','ok');
}

function exportJSON(){
  dl(JSON.stringify(Object.values(scan.results).filter(r=>r.status),null,2),'scan_results.json','application/json');
  addLog('JSON exported','ok');
}

function dl(content,filename,type){
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type}));
  a.download=filename;a.click();
}

function copyLog(){
  navigator.clipboard.writeText(document.getElementById('log').innerText);
  addLog('Log copied.','ok');
}

document.getElementById('start-btn').addEventListener('click',startScan);
document.getElementById('stop-btn').addEventListener('click',stopScan);
document.getElementById('clear-btn').addEventListener('click',clearAll);

// auto-detect subnet on load
fetch('/api/subnets').then(r=>r.json()).then(d=>{
  if(d.subnets&&d.subnets.length&&!document.getElementById('subnet').value){
    document.getElementById('subnet').value=d.subnets[0];
    addLog('Auto-detected subnet: '+d.subnets[0],'ok');
  }
});
addLog('Ping sweep tool v2 ready','ok');
addLog('Made by Karanam Shrivasta | github.com/mrshrivasta','info');
</script>
"""

# ── Page 2: Results table ──────────────────────────────────────────────────────
PAGE_RESULTS = """
<div class="page-header">
  <h1>📋 Scan Results</h1>
  <p>Full results table from the latest scan — filter, sort, export</p>
</div>
<div class="card">
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:.875rem">
    <input id="filter-input" placeholder="Filter by IP, OS, hostname..." style="flex:1;min-width:200px">
    <select id="filter-status" style="width:140px">
      <option value="all">All hosts</option>
      <option value="up">Hosts up only</option>
      <option value="down">No response only</option>
    </select>
    <button class="btn btn-gray" onclick="exportCSV2()" style="font-size:12px;padding:7px 14px">⬇ CSV</button>
    <button class="btn btn-gray" onclick="exportJSON2()" style="font-size:12px;padding:7px 14px">⬇ JSON</button>
  </div>
  <div style="overflow-x:auto">
    <table class="results-table" id="results-tbl">
      <thead>
        <tr>
          <th onclick="sortBy('ip')">IP ⇅</th>
          <th onclick="sortBy('status')">Status ⇅</th>
          <th onclick="sortBy('rtt')">RTT ⇅</th>
          <th onclick="sortBy('ttl')">TTL ⇅</th>
          <th>OS</th>
          <th>Device type</th>
          <th>Hostname</th>
          <th>Open ports</th>
          <th>Method</th>
        </tr>
      </thead>
      <tbody id="results-body"></tbody>
    </table>
  </div>
  <div id="results-empty" style="text-align:center;padding:2rem;color:var(--muted);font-size:14px">
    No scan data yet — run a scan on the Scanner page first.
  </div>
</div>
<div class="watermark">
  <div><div class="wm-name">Made by Karanam Shrivasta</div>
  <div class="wm-role">Network Security Educator</div></div>
  <div class="wm-links">
    <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank">LinkedIn</a>
    <a href="https://github.com/mrshrivasta" target="_blank">GitHub</a>
  </div>
</div>
<script>
let allData=[];let sortKey='ip';let sortAsc=true;
async function loadResults(){
  const r=await fetch('/api/results');
  allData=await r.json();
  render();
}
function render(){
  const filter=document.getElementById('filter-input').value.toLowerCase();
  const status=document.getElementById('filter-status').value;
  let data=allData.filter(r=>{
    if(status!=='all'&&r.status!==status)return false;
    const txt=(r.ip+r.os+r.hostname+r.device_type).toLowerCase();
    return txt.includes(filter);
  });
  data.sort((a,b)=>{
    let va=a[sortKey],vb=b[sortKey];
    if(sortKey==='ip'){
      const ai=a.ip.split('.').map(Number),bi=b.ip.split('.').map(Number);
      for(let i=0;i<4;i++)if(ai[i]!==bi[i])return sortAsc?ai[i]-bi[i]:bi[i]-ai[i];
      return 0;
    }
    if(va==null)va='';if(vb==null)vb='';
    return sortAsc?(va>vb?1:va<vb?-1:0):(va<vb?1:va>vb?-1:0);
  });
  const tbody=document.getElementById('results-body');
  const empty=document.getElementById('results-empty');
  if(!data.length){tbody.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  tbody.innerHTML=data.map(r=>`
    <tr>
      <td style="font-family:var(--mono);font-weight:600">${r.ip}</td>
      <td><span class="badge badge-${r.status}">${r.status==='up'?'✅ up':'— down'}</span></td>
      <td style="font-family:var(--mono)">${r.rtt!=null?r.rtt+'ms':'—'}</td>
      <td style="font-family:var(--mono)">${r.ttl||'—'}</td>
      <td>${(r.os_icon||'')+' '+(r.os||'—')}</td>
      <td>${r.device_type||'—'}</td>
      <td style="font-family:var(--mono);font-size:12px">${r.hostname||'—'}</td>
      <td>${(r.open_ports||[]).map(p=>`<span class="port-tag open">${p}</span>`).join('')||'—'}</td>
      <td style="font-size:12px;color:var(--muted)">${r.method||'—'}</td>
    </tr>`).join('');
}
function sortBy(k){if(sortKey===k)sortAsc=!sortAsc;else{sortKey=k;sortAsc=true;}render();}
document.getElementById('filter-input').addEventListener('input',render);
document.getElementById('filter-status').addEventListener('change',render);
function dl(content,filename,type){
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type}));
  a.download=filename;a.click();
}
function exportCSV2(){
  const rows=['IP,Status,RTT,TTL,OS,DeviceType,Hostname,OpenPorts,Method'];
  allData.forEach(r=>rows.push([r.ip,r.status,r.rtt!=null?r.rtt:'',r.ttl||'',r.os||'',r.device_type||'',r.hostname||'',(r.open_ports||[]).join(';'),r.method||''].join(',')));
  dl(rows.join('\\n'),'results.csv','text/csv');
}
function exportJSON2(){dl(JSON.stringify(allData,null,2),'results.json','application/json');}
loadResults();
</script>
"""

# ── Page 3: Port Scanner ──────────────────────────────────────────────────────
PAGE_PORTS = """
<div class="page-header">
  <h1>🔌 Port Scanner</h1>
  <p>Scan specific ports on a single target host</p>
</div>
<div class="disc" role="alert">
  <div class="disc-title">⚠️ Authorised use only</div>
  <div class="disc-body">Only scan hosts you own or have written permission to test. Made by Karanam Shrivasta.</div>
</div>
<div class="card">
  <div class="card-title">Target</div>
  <div class="form-row">
    <label>IP address</label>
    <input id="port-ip" placeholder="192.168.1.1" style="width:180px">
    <label>Port range</label>
    <input type="number" id="port-from" value="1" min="1" max="65535" style="width:70px">
    <span style="color:var(--muted)">–</span>
    <input type="number" id="port-to" value="1024" min="1" max="65535" style="width:70px">
  </div>
  <div class="card-title">Quick presets</div>
  <div class="tabs" id="preset-tabs">
    <div class="tab active" data-from="1" data-to="1024">Top 1024</div>
    <div class="tab" data-from="1" data-to="100">Top 100</div>
    <div class="tab" data-from="1" data-to="65535">Full scan</div>
    <div class="tab" data-from="22" data-to="22">SSH only</div>
    <div class="tab" data-from="80" data-to="443">Web ports</div>
  </div>
  <div class="form-row">
    <label>Timeout (s)</label>
    <input type="number" id="port-timeout" value="0.5" step="0.1" min="0.1" max="5" style="width:80px">
    <label>Threads</label>
    <input type="number" id="port-workers" value="100" min="1" max="500" style="width:80px">
    <button class="btn btn-blue" id="port-start">▶ Scan ports</button>
    <button class="btn btn-red" id="port-stop" style="display:none">⏸ Stop</button>
  </div>
</div>
<div class="card">
  <div class="card-title">Results</div>
  <div class="stats-grid">
    <div class="stat"><div class="stat-v" id="ps-total">0</div><div class="stat-l">scanned</div></div>
    <div class="stat"><div class="stat-v" id="ps-open" style="color:var(--green)">0</div><div class="stat-l">open</div></div>
    <div class="stat"><div class="stat-v" id="ps-pct">0%</div><div class="stat-l">complete</div></div>
  </div>
  <div class="bar-wrap"><div class="bar" id="ps-bar"></div></div>
  <div id="ps-status" style="font-size:12px;color:var(--muted);margin-bottom:.875rem">Ready</div>
  <div id="ps-results" style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:.875rem"></div>
  <div class="log-box" id="ps-log"></div>
</div>
<div class="watermark">
  <div><div class="wm-name">Made by Karanam Shrivasta</div></div>
  <div class="wm-links">
    <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank">LinkedIn</a>
    <a href="https://github.com/mrshrivasta" target="_blank">GitHub</a>
  </div>
</div>
<script>
let ps={es:null,done:0,total:0,open:0};
document.querySelectorAll('#preset-tabs .tab').forEach(t=>t.addEventListener('click',function(){
  document.querySelectorAll('#preset-tabs .tab').forEach(x=>x.classList.remove('active'));
  this.classList.add('active');
  document.getElementById('port-from').value=this.dataset.from;
  document.getElementById('port-to').value=this.dataset.to;
}));
function psLog(msg,type='info'){
  const el=document.getElementById('ps-log');
  el.innerHTML+=`<span class="${type}">[${new Date().toLocaleTimeString()}]</span> ${msg}\\n`;
  el.scrollTop=el.scrollHeight;
}
document.getElementById('port-start').addEventListener('click',()=>{
  const ip=document.getElementById('port-ip').value.trim();
  if(!ip){alert('Enter an IP address.');return;}
  const from=document.getElementById('port-from').value;
  const to=document.getElementById('port-to').value;
  const timeout=document.getElementById('port-timeout').value;
  const workers=document.getElementById('port-workers').value;
  ps={es:null,done:0,total:parseInt(to)-parseInt(from)+1,open:0};
  document.getElementById('ps-results').innerHTML='';
  document.getElementById('port-start').style.display='none';
  document.getElementById('port-stop').style.display='inline-flex';
  document.getElementById('ps-status').textContent='Scanning '+ip+' ports '+from+'–'+to+'...';
  psLog('Port scan: '+ip+' ports '+from+'-'+to,'info');
  ps.es=new EventSource('/api/portscan?ip='+encodeURIComponent(ip)+'&from='+from+'&to='+to+'&timeout='+timeout+'&workers='+workers);
  ps.es.addEventListener('port',ev=>{
    const d=JSON.parse(ev.data);ps.done++;
    document.getElementById('ps-total').textContent=ps.done;
    document.getElementById('ps-pct').textContent=Math.round(ps.done/ps.total*100)+'%';
    document.getElementById('ps-bar').style.width=(ps.done/ps.total*100)+'%';
    if(d.state==='open'){
      ps.open++;
      document.getElementById('ps-open').textContent=ps.open;
      const tag=document.createElement('span');
      tag.className='port-tag open';
      tag.textContent=d.port+'/'+(d.service||'?')+' [open]';
      document.getElementById('ps-results').appendChild(tag);
      psLog('OPEN: '+d.port+'/'+d.service,'ok');
    }
  });
  ps.es.addEventListener('done',ev=>{
    const d=JSON.parse(ev.data);
    document.getElementById('port-start').style.display='inline-flex';
    document.getElementById('port-stop').style.display='none';
    document.getElementById('ps-status').textContent='Done — '+d.open+' open ports found';
    psLog('Done. '+d.open+' open ports out of '+d.total+' scanned.','ok');
    if(ps.es)ps.es.close();
  });
  ps.es.onerror=()=>{
    document.getElementById('port-start').style.display='inline-flex';
    document.getElementById('port-stop').style.display='none';
    if(ps.es)ps.es.close();
  };
});
document.getElementById('port-stop').addEventListener('click',()=>{
  if(ps.es)ps.es.close();
  document.getElementById('port-start').style.display='inline-flex';
  document.getElementById('port-stop').style.display='none';
  psLog('Stopped.','warn');
});
</script>
"""

# ── Page 4: OS Detection ──────────────────────────────────────────────────────
PAGE_OS = """
<div class="page-header">
  <h1>💻 OS Detection</h1>
  <p>Fingerprint the operating system of a single host via TTL + port analysis</p>
</div>
<div class="card">
  <div class="card-title">Target host</div>
  <div class="form-row">
    <label>IP address</label>
    <input id="os-ip" placeholder="192.168.1.1" style="width:200px">
    <button class="btn btn-blue" id="os-scan">🔍 Detect OS</button>
  </div>
</div>
<div class="card" id="os-result" style="display:none">
  <div class="card-title">Fingerprint result</div>
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem">
    <div id="os-icon" style="font-size:48px"></div>
    <div>
      <div id="os-name" style="font-size:22px;font-weight:700"></div>
      <div id="os-conf-lbl" style="font-size:13px;color:var(--muted);margin-top:2px"></div>
    </div>
  </div>
  <table class="detail-tbl">
    <tr><td>IP address</td><td id="os-ip-out">—</td></tr>
    <tr><td>Status</td><td id="os-status">—</td></tr>
    <tr><td>RTT</td><td id="os-rtt">—</td></tr>
    <tr><td>TTL (raw)</td><td id="os-ttl">—</td></tr>
    <tr><td>TTL-based OS</td><td id="os-ttl-os">—</td></tr>
    <tr><td>Port-based OS</td><td id="os-port-os">—</td></tr>
    <tr><td>Device type</td><td id="os-dev">—</td></tr>
    <tr><td>Hostname</td><td id="os-host">—</td></tr>
    <tr><td>Detection method</td><td id="os-method">—</td></tr>
  </table>
  <div style="margin-top:.875rem">
    <div class="card-title">Open ports used for fingerprinting</div>
    <div id="os-ports"></div>
  </div>
</div>
<div class="card">
  <div class="card-title">TTL reference guide</div>
  <table class="results-table">
    <thead><tr><th>TTL range</th><th>Operating system</th><th>Notes</th></tr></thead>
    <tbody>
      <tr><td style="font-family:var(--mono)">1–64</td><td>🐧 Linux / macOS / Android</td><td style="color:var(--muted)">Default TTL=64</td></tr>
      <tr><td style="font-family:var(--mono)">65–128</td><td>🪟 Windows (all versions)</td><td style="color:var(--muted)">Default TTL=128</td></tr>
      <tr><td style="font-family:var(--mono)">129–255</td><td>🔌 Cisco / Network Devices</td><td style="color:var(--muted)">Default TTL=255</td></tr>
      <tr><td style="font-family:var(--mono)">any, 3389 open</td><td>🪟 Windows RDP server</td><td style="color:var(--muted)">High confidence</td></tr>
      <tr><td style="font-family:var(--mono)">any, 22+111 open</td><td>🐧 Linux server</td><td style="color:var(--muted)">High confidence</td></tr>
      <tr><td style="font-family:var(--mono)">any, 9100/631 open</td><td>🖨️ Network printer</td><td style="color:var(--muted)">Port-based only</td></tr>
    </tbody>
  </table>
</div>
<div class="watermark">
  <div><div class="wm-name">Made by Karanam Shrivasta</div></div>
  <div class="wm-links">
    <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank">LinkedIn</a>
    <a href="https://github.com/mrshrivasta" target="_blank">GitHub</a>
  </div>
</div>
<script>
document.getElementById('os-scan').addEventListener('click',async()=>{
  const ip=document.getElementById('os-ip').value.trim();
  if(!ip){alert('Enter an IP address.');return;}
  document.getElementById('os-scan').textContent='Scanning...';
  document.getElementById('os-result').style.display='none';
  const r=await fetch('/api/osdetect?ip='+encodeURIComponent(ip));
  const d=await r.json();
  document.getElementById('os-scan').textContent='🔍 Detect OS';
  document.getElementById('os-result').style.display='block';
  document.getElementById('os-icon').textContent=d.os_icon||'❓';
  document.getElementById('os-name').textContent=d.os||'Unknown';
  document.getElementById('os-conf-lbl').textContent='Confidence: '+(d.os_conf||'low');
  document.getElementById('os-ip-out').textContent=d.ip;
  document.getElementById('os-status').textContent=d.status==='up'?'✅ Online':'❌ No response';
  document.getElementById('os-rtt').textContent=d.rtt!=null?d.rtt+'ms':'—';
  document.getElementById('os-ttl').textContent=d.ttl||'—';
  document.getElementById('os-ttl-os').textContent=d.ttl_os||'—';
  document.getElementById('os-port-os').textContent=d.port_os||'—';
  document.getElementById('os-dev').textContent=d.device_type||'—';
  document.getElementById('os-host').textContent=d.hostname||'—';
  document.getElementById('os-method').textContent=d.method||'—';
  const pe=document.getElementById('os-ports');
  if(d.open_ports&&d.open_ports.length){
    pe.innerHTML=d.open_ports.map(p=>`<span class="port-tag open">${p}</span>`).join('');
  } else {
    pe.innerHTML='<span style="font-size:12px;color:var(--muted)">No open ports detected</span>';
  }
});
</script>
"""

# ── Page 5: About / Help ──────────────────────────────────────────────────────
PAGE_ABOUT = """
<div class="page-header">
  <h1>ℹ️ About / Help</h1>
  <p>Documentation, CLI reference, and legal information</p>
</div>
<div class="card">
  <div class="card-title">What this tool does</div>
  <table class="results-table">
    <thead><tr><th>Feature</th><th>How it works</th></tr></thead>
    <tbody>
      <tr><td>ICMP ping</td><td>OS subprocess ping — parses RTT + TTL from stdout on Windows/Linux/macOS</td></tr>
      <tr><td>TCP fallback</td><td>If ICMP is firewalled, tries TCP connect on common ports — host marked up if any respond</td></tr>
      <tr><td>Port scanning</td><td>Full TCP connect — no root needed. Concurrent per-host with ThreadPoolExecutor</td></tr>
      <tr><td>Reverse DNS</td><td>socket.gethostbyaddr with configurable timeout</td></tr>
      <tr><td>OS detection</td><td>TTL range analysis + open-port fingerprinting combined for high-confidence guess</td></tr>
      <tr><td>Device type</td><td>Port pattern matching: WINDOWS_PORTS, LINUX_PORTS, PRINTER_PORTS, ROUTER_PORTS</td></tr>
      <tr><td>Real-time stream</td><td>Server-Sent Events (SSE) — each host result streams to browser as it completes</td></tr>
      <tr><td>Export</td><td>CSV and JSON download from both Scanner and Results pages</td></tr>
    </tbody>
  </table>
</div>
<div class="card">
  <div class="card-title">CLI reference</div>
  <div style="background:#0f172a;border-radius:10px;padding:1rem;font-family:var(--mono);
              font-size:12px;line-height:2;color:#94a3b8">
    <span style="color:#4ade80">python ping_sweep.py</span><br>
    <span style="color:#4ade80">python ping_sweep.py</span> <span style="color:#60a5fa">--subnet 192.168.0 --start 1 --end 254</span><br>
    <span style="color:#4ade80">python ping_sweep.py</span> <span style="color:#60a5fa">--ports 22,80,443,3389 --workers 80 --timeout 1.5</span><br>
    <span style="color:#4ade80">python ping_sweep.py</span> <span style="color:#60a5fa">--all-ports --csv out.csv --json out.json</span><br>
    <span style="color:#4ade80">python ping_sweep.py</span> <span style="color:#fbbf24">--web</span>  <span style="color:#64748b"># launches this UI on :5000</span>
  </div>
</div>
<div class="card">
  <div class="card-title">Troubleshooting</div>
  <table class="results-table">
    <thead><tr><th>Problem</th><th>Solution</th></tr></thead>
    <tbody>
      <tr><td>0 hosts found</td><td>Your subnet may differ — click Auto-detect or try 192.168.0.x or 10.0.0.x</td></tr>
      <tr><td>RTT = null on Windows</td><td>Run as Administrator so ICMP responses aren't blocked</td></tr>
      <tr><td>All hosts "down"</td><td>ICMP may be firewalled — tool falls back to TCP; ensure ports 80/443/22 are in the port list</td></tr>
      <tr><td>Hostname = null</td><td>rDNS not configured on your router — normal for home networks</td></tr>
      <tr><td>Slow scan</td><td>Increase threads slider to Fast; reduce timeout to 0.5s</td></tr>
      <tr><td>OS = Unknown</td><td>Enable port scanning — OS fingerprinting improves with more open ports detected</td></tr>
      <tr><td>Port scanner empty</td><td>Target may have a firewall dropping packets; try shorter timeout 0.3s</td></tr>
    </tbody>
  </table>
</div>
<div class="card">
  <div class="card-title">Legal disclaimer</div>
  <div style="font-size:13px;line-height:1.9;color:var(--muted)">
    <p>This tool is provided <strong style="color:var(--text)">strictly for educational, research, and legitimate security testing purposes</strong> on networks you own or have <strong style="color:var(--text)">explicit written permission</strong> to scan.</p><br>
    <p>Unauthorised network scanning may violate:</p>
    <ul style="margin:.5rem 0 .5rem 1.5rem">
      <li><strong style="color:var(--text)">Computer Fraud and Abuse Act (CFAA)</strong> — United States</li>
      <li><strong style="color:var(--text)">Computer Misuse Act 1990</strong> — United Kingdom</li>
      <li><strong style="color:var(--text)">Information Technology Act 2000</strong> — India</li>
      <li>Equivalent laws in your jurisdiction</li>
    </ul>
    <p><strong style="color:var(--text)">Karanam Shrivasta</strong> and all contributors assume <strong style="color:var(--text)">zero liability</strong> for any misuse, damage, or le    <p><strong style="color:var(--text)">Karanam Shrivasta</strong> and all contributors assume <strong style="color:var(--text)">zero liability</strong> for any misuse, damage, or legal consequences.</p>
  </div>
</div>
<div class="card">
  <div class="card-title">Author</div>
  <div style="display:flex;align-items:center;gap:1rem">
    <div style="width:56px;height:56px;border-radius:50%;background:#DBEAFE;display:flex;
                align-items:center;justify-content:center;font-size:20px;font-weight:700;color:#1e40af">KS</div>
    <div>
      <div style="font-size:16px;font-weight:700">Karanam Shrivasta</div>
      <div style="font-size:13px;color:var(--muted);margin-top:2px">Network Security Educator · Ethical Hacking Researcher · Open Source Developer</div>
      <div style="margin-top:8px;display:flex;gap:10px">
        <a href="https://www.linkedin.com/in/karanam-shrivasta/" target="_blank" rel="noopener"
           style="font-size:13px;color:var(--blue);font-weight:500;text-decoration:none">LinkedIn ↗</a>
        <a href="https://github.com/mrshrivasta" target="_blank" rel="noopener"
           style="font-size:13px;color:var(--blue);font-weight:500;text-decoration:none">GitHub ↗</a>
      </div>
    </div>
  </div>
</div>
"""


def web_mode():
    try:
        from flask import Flask, request, jsonify, Response, stream_with_context
    except ImportError:
        print("Flask not installed. Run:  pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    _results_store: list[dict] = []

    @app.route("/")
    def r_scan():
        return page(PAGE_SCAN, "scan", "Scanner")

    @app.route("/results")
    def r_results():
        return page(PAGE_RESULTS, "results", "Results")

    @app.route("/ports")
    def r_ports():
        return page(PAGE_PORTS, "ports", "Port Scanner")

    @app.route("/osdetect")
    def r_os():
        return page(PAGE_OS, "os", "OS Detection")

    @app.route("/about")
    def r_about():
        return page(PAGE_ABOUT, "about", "About / Help")

    @app.route("/api/subnets")
    def api_subnets():
        return jsonify({"subnets": get_local_subnets()})

    @app.route("/api/results")
    def api_results():
        return jsonify(_results_store)

    @app.route("/api/scan")
    def api_scan():
        subnet  = request.args.get("subnet", "192.168.1")
        start   = int(request.args.get("start", 1))
        end     = int(request.args.get("end", 50))
        ports   = [int(p) for p in request.args.get("ports","22,80,443").split(",") if p.strip().isdigit()]
        workers = int(request.args.get("workers", 50))
        _results_store.clear()

        def generate():
            import json as _j
            targets = [f"{subnet}.{i}" for i in range(start, end + 1)]
            up = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(scan_host, ip, ports, 1.5, True): ip for ip in targets}
                for fut in concurrent.futures.as_completed(futs):
                    res = fut.result()
                    _results_store.append(res)
                    if res["status"] == "up":
                        up += 1
                    yield f"event: result\ndata: {_j.dumps(res)}\n\n"
            yield f"event: done\ndata: {_j.dumps({'up':up,'total':len(targets)})}\n\n"

        return Response(stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

    @app.route("/api/portscan")
    def api_portscan():
        ip        = request.args.get("ip", "")
        port_from = int(request.args.get("from", 1))
        port_to   = int(request.args.get("to", 1024))
        timeout   = float(request.args.get("timeout", 0.5))
        workers   = int(request.args.get("workers", 100))
        ports     = list(range(port_from, port_to + 1))

        def generate():
            import json as _j
            open_count = 0
            def check(port):
                open_ = tcp_connect(ip, port, timeout)
                return {"port":port,"state":"open" if open_ else "closed",
                        "service":PORT_SERVICES.get(port,"unknown")}
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                for res in ex.map(check, ports):
                    if res["state"] == "open":
                        open_count += 1
                    yield f"event: port\ndata: {_j.dumps(res)}\n\n"
            yield f"event: done\ndata: {_j.dumps({'open':open_count,'total':len(ports)})}\n\n"

        return Response(stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

    @app.route("/api/osdetect")
    def api_osdetect():
        ip = request.args.get("ip", "")
        r  = scan_host(ip, ports=COMMON_PORTS, timeout=2.0, do_dns=True)
        ttl_os = None
        if r["ttl"]:
            for rng, name, _ in OS_SIGNATURES:
                if r["ttl"] in rng:
                    ttl_os = name; break
        open_set = set(r["open_ports"])
        port_os = None
        if open_set & WINDOWS_PORTS: port_os = "Windows"
        elif open_set & LINUX_PORTS:  port_os = "Linux / macOS"
        elif open_set & PRINTER_PORTS: port_os = "Network Printer"
        r["ttl_os"]  = ttl_os
        r["port_os"] = port_os
        return jsonify(r)

    print("\n" + "="*60)
    print("  Ping Sweep / Host Discovery v2.0 — 5-page web UI")
    print("  Made by Karanam Shrivasta")
    print("  http://localhost:5000/          Scanner")
    print("  http://localhost:5000/results   Results table")
    print("  http://localhost:5000/ports     Port scanner")
    print("  http://localhost:5000/osdetect  OS detection")
    print("  http://localhost:5000/about     Help / docs")
    print("="*60 + "\n")
    app.run(debug=False, port=5000, threaded=True)


if __name__ == "__main__":
    cli_mode()