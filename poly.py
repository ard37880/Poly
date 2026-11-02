#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Poly - a recon and enumeration console
A single-file terminal console that scans a host or URL and tells you what to
look at next: a target board that RUNS recon/enumeration (two-stage nmap,
searchsploit, directory brute, service enum), a scan summary with next-step
hints, an arsenal that locates your wordlists and payload references, a results
search, an offline cheat sheet, and a session report exporter. Standard library
only.

    python3 poly.py

Tooling knobs live in the CONFIG block at the top. MIT-licensed; see LICENSE.

AUTHORIZATION: the scan features run real tools (nmap, searchsploit, whatweb,
feroxbuster, ffuf, gobuster, nikto, netexec) against hosts you name. Only run
them against systems you have explicit, written authorization to test, and
nothing else. Poly confirms authorization before every active scan. It never
runs exploits or reverse shells.
"""

import os
import re
import ssl
import sys
import json
import shutil
import datetime
import ipaddress
import urllib.parse
import urllib.error
import urllib.request
import subprocess
import xml.etree.ElementTree as ET

# ======================================================================
# CONFIG  -  edit this for your own event and team
# ======================================================================
CONFIG = {
    "name": "POLY",                      # shown in the banner
    "subtitle": "recon + enumeration console",
    "state_dir": "",                     # state/results dir, or "" = next to this file

    # --- tooling (tune the scan without editing the code below) ---
    "dir_tool": "feroxbuster",   # directory brute tool: feroxbuster | gobuster | dirb (falls back to whatever is installed)
    "dir_wordlist": "",          # "" = auto-detect a common list; or set an absolute path
    "nmap_timing": "-T4",        # nmap timing template (-T4 fast, -T3 reliable on a lossy link)
    "udp_top_ports": "20",       # how many top UDP ports the deep scan sweeps
    "vhost_domain": "",          # e.g. "htb" or "example.com" -> deep scan fuzzes vhosts; "" disables it
    "keep_raw_files": False,     # False = one tidy scan folder (summary.md + nmap.xml + details.txt); True = keep every raw tool file
}

# Team roles. Put a name in the first field, or leave it "" for unassigned.

# ======================================================================
# content  -  generic CTF reference; edit freely
# ======================================================================



LINKS = [
    ("HackTricks (methodology)", "https://book.hacktricks.xyz/"),
    ("GTFOBins (privesc ref)", "https://gtfobins.github.io/"),
    ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings"),
    ("revshells (generator)", "https://www.revshells.com/"),
    ("explainshell", "https://explainshell.com/"),
]

# "I have X, what tool do I use?" -> situation mapped to tool + first command.
ADVISOR = [
    ("An open port / running service", [
        "Follow the NEXT STEPS Poly printed per service after the scan.",
        "General: nmap -sV first, then the service's own enum (SMB -> enum4linux-ng, SNMP -> snmpwalk).",
    ]),
    ("A web app / URL", [
        "whatweb to fingerprint, then feroxbuster / ffuf / gobuster for paths, nikto for quick issues.",
        "Always check /robots.txt /.git/ /.env ; inspect response headers by hand (curl -sI URL).",
    ]),
    ("SMB / Windows host (445/139)", [
        "netexec smb <host>  (shares, signing, null session), then enum4linux-ng <host>.",
        "Anonymous share? smbclient -N -L //<host>/ and pull what you can read.",
    ]),
    ("A login / service you have creds for", [
        "Spray carefully and only in scope: hydra for the protocol, or the service's own client.",
        "Reuse creds across services; check for default and weak passwords first.",
    ]),
    ("A found hash to crack", [
        "hash-identifier (or hashid) to ID the type.",
        "john --wordlist=rockyou.txt hash.txt   OR   hashcat -m <mode> hash.txt rockyou.txt",
    ]),
]

SETUP_SCRIPT = r"""#!/usr/bin/env bash
# Role-aware tool setup. Detects apt vs pacman.
# Installs standard, freely-available security tooling.
# Usage:  bash setup.sh
set -e
if command -v apt >/dev/null 2>&1; then
  PM="sudo apt install -y"; sudo apt update
elif command -v pacman >/dev/null 2>&1; then
  PM="sudo pacman -S --needed --noconfirm"
else
  echo "No apt or pacman found. Install tools by hand."; exit 1
fi
echo "[*] Core triage"
$PM nmap curl wget git python3 python3-pip file binwalk exiftool steghide foremost gdb radare2 || true
echo "[*] Web + recon"
$PM feroxbuster ffuf gobuster dirb sqlmap whatweb nikto recon-ng exploitdb seclists enum4linux-ng || true
echo "[*] SMB / AD + pivoting"
$PM chisel ligolo-ng 2>/dev/null || true
command -v pipx >/dev/null 2>&1 || $PM pipx || true
pipx install netexec 2>/dev/null || true   # crackmapexec successor (smb/winrm/ldap enum)
echo "[*] Python libs (pip)"
pip install --user pwntools pycryptodome sympy gmpy2 2>/dev/null || pip install --break-system-packages pwntools pycryptodome sympy gmpy2 || true
echo "[*] Memory forensics"
command -v pipx >/dev/null 2>&1 || $PM pipx || true
pipx install volatility3 2>/dev/null || true
echo "[*] Done. Bookmark CyberChef (gchq.github.io/CyberChef) and install Ghidra or Binary Ninja separately."
"""

# ======================================================================
# skull banner
# ======================================================================
LOGO = r"""
    ██████╗  ██████╗ ██╗  ██╗   ██╗████████╗ ██████╗  ██████╗ ██╗
    ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║
    ██████╔╝██║   ██║██║   ╚████╔╝    ██║   ██║   ██║██║   ██║██║
    ██╔═══╝ ██║   ██║██║    ╚██╔╝     ██║   ██║   ██║██║   ██║██║
    ██║     ╚██████╔╝███████╗██║      ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝      ╚═════╝ ╚══════╝╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""
TAGLINE = "# recon + enumeration console"

# ======================================================================
# colours
# ======================================================================
class C:
    R = "\033[31m"
    BR = "\033[91m"
    G = "\033[32m"
    Y = "\033[33m"
    B = "\033[34m"
    CY = "\033[36m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    X = "\033[0m"

# ----------------------------------------------------------------------
# state location (shared folder support)
# ----------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATE = os.environ.get("POLY_STATE") or CONFIG.get("state_dir") or _HERE
try:
    os.makedirs(_STATE, exist_ok=True)
except Exception:
    _STATE = _HERE
TARGETS_FILE = os.path.join(_STATE, "poly_targets.json")
RESULTS_DIR = os.path.join(_STATE, "results")

WORDLIST = next((w for w in [
    CONFIG.get("dir_wordlist", ""),
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
] if w and os.path.exists(w)), None)

SCAN_TIMEOUT = 1800  # seconds, per tool

def _dir_cmd(url, outpath):
    """Build the directory-brute command from CONFIG['dir_tool'], falling back
    to whatever is actually installed. Returns (label, argv) or None."""
    pref = (CONFIG.get("dir_tool") or "feroxbuster").lower()
    order = [pref] + [t for t in ("feroxbuster", "ffuf", "gobuster", "dirb") if t != pref]
    for tool in order:
        if shutil.which(tool) is None:
            continue
        # all of these print results to stdout; _run_tool captures that to outpath
        if tool == "feroxbuster":
            cmd = ["feroxbuster", "-u", url, "--silent", "--no-state"]
            if WORDLIST:
                cmd += ["-w", WORDLIST]
            return ("feroxbuster", cmd)
        if tool == "ffuf" and WORDLIST:
            return ("ffuf", ["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", WORDLIST, "-ac", "-s"])
        if tool == "gobuster" and WORDLIST:
            return ("gobuster", ["gobuster", "dir", "-q", "-u", url, "-w", WORDLIST])
        if tool == "dirb":
            return ("dirb", ["dirb", url] + ([WORDLIST] if WORDLIST else []))
    return None

# ----------------------------------------------------------------------
# target input: accept an IP (optional :port) OR a link, detect + parse
# ----------------------------------------------------------------------
def classify_target(raw):
    """Return dict: kind ('host'|'web'), host, port, scheme, path, display."""
    s = raw.strip()
    if not s:
        return None
    if "://" in s:
        u = urllib.parse.urlparse(s)
        host = u.hostname or ""
        port = u.port
        return {"kind": "web", "host": host, "port": port, "scheme": u.scheme,
                "path": u.path or "/", "display": s}
    host_part, _, port_part = s.partition(":")
    port = None
    if port_part and port_part.split("/")[0].isdigit():
        port = int(port_part.split("/")[0])
    is_ip = False
    try:
        ipaddress.ip_address(host_part)
        is_ip = True
    except ValueError:
        is_ip = False
    has_path = "/" in s
    if has_path:
        return {"kind": "web", "host": host_part, "port": port, "scheme": "http",
                "path": "/" + s.split("/", 1)[1], "display": s}
    return {"kind": "host", "host": host_part, "port": port, "scheme": None,
            "path": None, "display": s, "is_ip": is_ip}

WEB_METHOD = [
    "robots.txt, sitemap.xml, /.git/, view-source + HTML comments.",
    "Directory + file brute: ffuf / feroxbuster / gobuster.",
    "Test every parameter for SQLi (sqlmap), then LFI/RFI, command injection, path traversal.",
    "Check cookies, headers, and auth. Try default / weak creds.",
    "Route through Burp (FoxyProxy) to see and replay requests.",
]
HOST_METHOD = [
    "Full service scan: nmap -sV -sC -p- against the host, then enumerate each open port.",
    "Low-hanging: anonymous FTP, open SMB shares, exposed admin panels.",
    "Match service versions to known CVEs (searchsploit --nmap does this from the scan).",
    "After a foothold: enumerate for privesc (GTFOBins, sudo -l, SUID).",
    "Pivot: from this host, nmap/forward to hosts beyond the local subnet.",
]

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")



def header():
    # cyan -> blue -> purple gradient, one shade per row (256-color)
    shades = [51, 45, 39, 33, 63, 99, 135]
    rows = LOGO.strip("\n").split("\n")
    print()
    for i, row in enumerate(rows):
        print(f"\033[1;38;5;{shades[min(i, len(shades)-1)]}m{row}{C.X}")
    print(f"    {C.Y}{TAGLINE}{C.X}\n")
    print(f"  {C.BOLD}{C.W}{CONFIG['name']}{C.X}  {C.DIM}{CONFIG['subtitle']}{C.X}")
    if _STATE != _HERE:
        print(f"  {C.DIM}state: {_STATE}{C.X}")
    print(C.DIM + "  " + "-" * 64 + C.X)

def pause():
    input(f"\n  {C.DIM}[enter to go back]{C.X} ")

def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _save(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"  {C.R}could not save: {e}{C.X}")

def _ts():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def _safe(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "target"

# ----------------------------------------------------------------------
# nmap parsing + next-step hints
# ----------------------------------------------------------------------
def _parse_nmap_xml(path):
    rows = []
    try:
        root = ET.parse(path).getroot()
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                st = port.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = port.find("service")
                rows.append({
                    "port": port.get("portid", "?"),
                    "proto": port.get("protocol", "tcp"),
                    "service": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                })
    except Exception:
        return []
    return rows

def _open_ports(xmlp):
    """Just the open TCP port numbers from an nmap XML (feeds stage 2)."""
    ports = []
    try:
        root = ET.parse(xmlp).getroot()
        for port in root.iter("port"):
            st = port.find("state")
            if st is not None and st.get("state") == "open":
                ports.append(port.get("portid"))
    except Exception:
        pass
    return ports

def _parse_scripts(xmlp):
    """Return [(port, script_id, output)] from nmap -sC XML (host- and port-level)."""
    out = []
    try:
        root = ET.parse(xmlp).getroot()
        for host in root.findall("host"):
            for scr in host.findall("./hostscript/script"):
                out.append(("-", scr.get("id", ""), (scr.get("output") or "").strip()))
            for port in host.findall("./ports/port"):
                pid = port.get("portid", "?")
                for scr in port.findall("script"):
                    out.append((pid, scr.get("id", ""), (scr.get("output") or "").strip()))
    except Exception:
        pass
    return out

# the -sC scripts whose output is actually a lead worth surfacing
_LEAD_SCRIPTS = {
    "http-title": "http title", "http-server-header": "server", "http-generator": "generator",
    "http-robots.txt": "robots.txt", "http-git": ".git exposed", "http-ls": "dir listing",
    "ftp-anon": "ANON FTP", "ssl-cert": "TLS cert", "smb-os-discovery": "SMB",
    "smb-enum-shares": "SMB shares", "smb2-security-mode": "SMB signing",
    "nbstat": "NetBIOS", "http-auth": "http auth", "http-cookie-flags": "cookies",
}

def _script_findings(scripts):
    """One tidy line per interesting script output, for the terminal + files."""
    out = []
    for pid, sid, text in scripts:
        if sid not in _LEAD_SCRIPTS or not text:
            continue
        flat = " ".join(text.split())
        if len(flat) > 140:
            flat = flat[:140] + "..."
        where = f"{pid}/" if pid != "-" else ""
        out.append(f"{where}{_LEAD_SCRIPTS[sid]}: {flat}")
    return out

def _hostnames_from_scripts(scripts, host):
    """Pull .htb-style hostnames out of TLS certs and HTTP redirects for /etc/hosts."""
    names = set()
    for _, sid, text in scripts:
        if sid == "ssl-cert":
            for m in re.findall(r"commonName=([A-Za-z0-9.*\-]+)", text):
                names.add(m)
            for m in re.findall(r"DNS:([A-Za-z0-9.*\-]+)", text):
                names.add(m)
        if sid == "http-title":
            for m in re.findall(r"redirect to https?://([A-Za-z0-9.\-]+)", text):
                names.add(m)
    good = []
    for n in names:
        n = n.lstrip("*.")
        if n and "." in n and not n[0].isdigit() and n != host and n not in good:
            good.append(n)
    return sorted(good)

def _service_hint(service, port, host):
    s = (service or "").lower()
    H = {
        "ftp": f"ftp {host}  (try anonymous) ; nmap --script ftp-anon -p{port} {host}",
        "ssh": f"ssh user@{host} -p {port}  (note the version)",
        "http": f"gobuster dir -u http://{host}:{port}/ -w /usr/share/wordlists/dirb/common.txt ; whatweb http://{host}:{port}/ ; check /robots.txt /.git /.env",
        "microsoft-ds": f"enum4linux-ng {host} ; smbclient -L //{host}/ -N ; smbmap -H {host}",
        "netbios-ssn": f"enum4linux-ng {host} ; smbclient -L //{host}/ -N",
        "snmp": f"snmpwalk -v2c -c public {host}",
        "tftp": f"tftp {host}  (get a known filename - no listing) ; nmap -sU --script tftp-enum -p{port} {host}",
        "ldap": f"ldapsearch -x -H ldap://{host}:{port} -s base namingContexts",
        "rpcbind": f"rpcinfo -p {host} ; showmount -e {host}",
        "nfs": f"showmount -e {host}",
        "mysql": f"mysql -h {host} -P {port} -u root -p",
        "ms-sql-s": f"impacket-mssqlclient user@{host}",
        "postgresql": f"psql -h {host} -p {port} -U postgres",
        "redis": f"redis-cli -h {host} -p {port}  (INFO ; KEYS *)",
        "domain": f"dig axfr @{host} <domain>  (zone transfer)",
        "smtp": f"nmap --script smtp-enum-users,smtp-commands -p{port} {host}",
        "pop3": f"nc {host} {port}  (USER / PASS / LIST / RETR)",
        "imap": f"nc {host} {port}",
        "rdp": f"xfreerdp /u:user /v:{host}:{port}",
        "telnet": f"telnet {host} {port}",
    }
    if s in H:
        return H[s]
    if "http" in s:
        scheme = "https" if ("ssl" in s or str(port) in ("443", "8443")) else "http"
        return (f"gobuster dir -u {scheme}://{host}:{port}/ -w /usr/share/wordlists/dirb/common.txt"
                + (" -k" if scheme == "https" else "")
                + f" ; whatweb {scheme}://{host}:{port}/ ; check /robots.txt /.git /.env")
    return None

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

def _strip_ansi(s):
    """Remove ANSI colour/escape sequences (searchsploit highlights matches)."""
    return _ANSI_RE.sub("", s)

def _top_cves(scan_dir, limit=8):
    """The useful rows out of searchsploit.txt, for the terminal + summary."""
    if not scan_dir:
        return []
    sp = os.path.join(scan_dir, "searchsploit.txt")
    if not os.path.exists(sp):
        return []
    hits = []
    try:
        for line in open(sp, encoding="utf-8", errors="replace"):
            ln = _strip_ansi(line).strip()
            if not ln or ln.startswith("$") or ln.startswith("#"):
                continue
            if set(ln) <= set("-| "):          # table separator row (dashes/pipes)
                continue
            if "Exploit Title" in ln or "Shellcodes" in ln:
                continue
            if "|" in ln:                      # a result row: "Title | path"
                hits.append(" ".join(ln.split()))
            if len(hits) >= limit:
                break
    except Exception:
        pass
    return hits

def _scan_summary(t, xmlp, scan_dir=None, udp_rows=None):
    rows = _parse_nmap_xml(xmlp)
    udp_rows = udp_rows or []
    if not rows and not udp_rows:
        print(f"\n  {C.Y}no open ports parsed from the scan.{C.X}")
        print(f"  {C.DIM}if you expected some: the box may be booting, your VPN/route to it may be")
        print(f"  down, or it's fully filtered. Sanity-check reachability with:{C.X}")
        print(f"    {C.W}nmap -Pn -p22 {t['host']}{C.X}")
        if scan_dir:
            try:
                with open(os.path.join(scan_dir, "summary.md"), "w", encoding="utf-8") as f:
                    f.write(f"# {t['display']} - scan summary\n\n")
                    f.write("No open ports parsed. Host may be down/filtered, or the VPN/route is down.\n")
            except Exception:
                pass
        return
    host = t["host"]
    t["services"] = [f"{r['port']}/{r['proto']} {r['service']} {r['product']} {r['version']}".strip()
                     for r in rows + udp_rows]
    cves = _top_cves(scan_dir)
    scripts = _parse_scripts(xmlp)
    findings = _script_findings(scripts)
    hostnames = _hostnames_from_scripts(scripts, host)
    t["script_findings"] = findings
    t["hostnames"] = hostnames

    # numbered next-step list (service -> command), stored for copy-by-number
    steps, seen = [], set()
    for r in rows + udp_rows:
        hint = _service_hint(r["service"], r["port"], host)
        if hint and r["service"] not in seen:
            seen.add(r["service"]); steps.append((r["service"], hint))
    t["next_steps"] = steps

    # --- important info, on the terminal ---
    print(f"\n  {C.BOLD}{C.W}OPEN PORTS{C.X}  {C.DIM}({len(rows)} tcp"
          + (f", {len(udp_rows)} udp" if udp_rows else "") + f"){C.X}")
    for r in rows:
        ver = f"{r['product']} {r['version']}".strip()
        print(f"    {C.G}{r['port']:>5}/{r['proto']:<3}{C.X} {C.W}{r['service']:<14}{C.X} {C.DIM}{ver}{C.X}")
    for r in udp_rows:
        ver = f"{r['product']} {r['version']}".strip()
        print(f"    {C.Y}{r['port']:>5}/{r['proto']:<3}{C.X} {C.W}{r['service']:<14}{C.X} {C.DIM}{ver}{C.X}")
    if findings:
        print(f"\n  {C.BOLD}{C.W}SCRIPT FINDINGS{C.X}  {C.DIM}(from nmap -sC - the real leads){C.X}")
        for ln in findings:
            print(f"    {C.Y}-{C.X} {ln}")
    print(f"\n  {C.BOLD}{C.W}NEXT STEPS{C.X}  {C.DIM}(run by hand){C.X}")
    for i, (svc, hint) in enumerate(steps):
        print(f"    {C.G}[{i}]{C.X} {C.CY}{svc}{C.X}: {hint}")
    if cves:
        print(f"\n  {C.BOLD}{C.R}POSSIBLE EXPLOITS{C.X}  {C.DIM}(searchsploit - verify before you trust them){C.X}")
        for ln in cves[:6]:
            print(f"    {C.DIM}-{C.X} {ln[:104]}")
    elif scan_dir and os.path.exists(os.path.join(scan_dir, "searchsploit.txt")):
        print(f"\n  {C.DIM}searchsploit: no version-matched exploits (SSH/HTTP CVEs rarely are the way).{C.X}")
    if hostnames:
        print(f"\n  {C.Y}hostname(s) seen:{C.X} {C.W}{', '.join(hostnames)}{C.X}  {C.DIM}(add to /etc/hosts below){C.X}")

    # --- same thing, persisted to summary.md ---
    if scan_dir:
        try:
            with open(os.path.join(scan_dir, "summary.md"), "w", encoding="utf-8") as f:
                f.write(f"# {t['display']} - scan summary\n\n")
                f.write(f"_Generated {datetime.datetime.now().isoformat(timespec='seconds')}_  \n")
                f.write(f"Host: {host}\n\n## Open ports\n\n")
                for r in rows + udp_rows:
                    ver = f"{r['product']} {r['version']}".strip()
                    f.write(f"- **{r['port']}/{r['proto']}** {r['service']}  {ver}\n")
                if findings:
                    f.write("\n## Script findings (nmap -sC)\n\n")
                    for ln in findings:
                        f.write(f"- {ln}\n")
                if hostnames:
                    f.write("\n## Hostnames (for /etc/hosts)\n\n")
                    f.write(f"- `{host} {' '.join(hostnames)}`\n")
                f.write("\n## Next steps (by hand)\n\n")
                for svc, hint in steps:
                    f.write(f"- `{svc}`: {hint}\n")
                f.write("\n## Possible exploits (searchsploit)\n\n")
                if cves:
                    for ln in cves:
                        f.write(f"- {ln}\n")
                else:
                    f.write("_none version-matched_\n")
        except Exception:
            pass

# ----------------------------------------------------------------------
# flag catcher
# ----------------------------------------------------------------------
def _iter_result_files():
    """Every file under results/, recursing into the per-scan subfolders."""
    if not os.path.isdir(RESULTS_DIR):
        return
    for dirpath, _, files in os.walk(RESULTS_DIR):
        for fn in sorted(files):
            yield os.path.join(dirpath, fn)


# ----------------------------------------------------------------------
# active recon  -  runs standard tools, saves output to results/
# ----------------------------------------------------------------------
def _run_tool(cmd, outpath):
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"{C.DIM}skipped ({exe} not installed){C.X}"
    try:
        with open(outpath, "w", encoding="utf-8", errors="replace") as f:
            f.write("$ " + " ".join(cmd) + "\n")
            f.write("# " + datetime.datetime.now().isoformat(timespec="seconds") + "\n\n")
            f.flush()
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=SCAN_TIMEOUT)
        return f"{C.G}done{C.X} (rc={proc.returncode})  ->  {C.CY}{outpath}{C.X}"
    except subprocess.TimeoutExpired:
        return f"{C.Y}timed out{C.X} after {SCAN_TIMEOUT // 60}m (partial)  ->  {C.CY}{outpath}{C.X}"
    except Exception as e:
        return f"{C.R}error: {e}{C.X}"

def _run_nmap(t, scan_dir):
    """Two-stage TCP nmap: a fast full-range sweep to find open ports, then
    -sV -sC against ONLY those ports. Faster than one -sV -sC -p- and just as
    reliable. Returns (nmap_xml_path, [open ports]) and prints progress."""
    host = t["host"]
    timing = CONFIG.get("nmap_timing") or "-T4"
    stage1_xml = os.path.join(scan_dir, "nmap_ports.xml")
    nmap_xml = os.path.join(scan_dir, "nmap.xml")
    print(f"  {C.B}nmap 1/2{C.X}  {C.DIM}full-range sweep, all 65535 ports (-Pn -p- {timing}){C.X}")
    print(f"    {_run_tool(['nmap', '-Pn', '-p-', timing, '-oX', stage1_xml, host], os.path.join(scan_dir, 'nmap_ports.txt'))}")
    ports = _open_ports(stage1_xml)
    if not ports:
        return nmap_xml, []
    plist = ",".join(ports)
    print(f"    {C.G}{len(ports)} open:{C.X} {C.W}{plist}{C.X}")
    print(f"  {C.B}nmap 2/2{C.X}  {C.DIM}service + default scripts on open ports (-sV -sC){C.X}")
    print(f"    {_run_tool(['nmap', '-sV', '-sC', '-Pn', '-p', plist, timing, '-oX', nmap_xml, host], os.path.join(scan_dir, 'nmap.txt'))}")
    return nmap_xml, ports

def _web_present(t, rows):
    """True if this looks like a web target: web kind, or an http service open."""
    if t["kind"] == "web":
        return True
    return any("http" in (r.get("service") or "").lower() for r in rows)

def _smb_present(rows):
    return any((r.get("service") or "").lower() in ("microsoft-ds", "netbios-ssn")
               or r.get("port") in ("445", "139") for r in rows)

def _extra_jobs(t, scan_dir, nmap_xml, rows, deep=False, udp=False):
    """Non-nmap recon jobs as (label, command, outpath), written in scan_dir.
    searchsploit always; UDP, SMB enum (netexec) and the web enum tools are
    opt-in via deep/udp. Uses CONFIG for the dir tool, timing and vhost domain."""
    host = t["host"]
    timing = CONFIG.get("nmap_timing") or "-T4"

    def p(name):
        return os.path.join(scan_dir, name)

    jobs = [("searchsploit", ["searchsploit", "--nmap", nmap_xml], p("searchsploit.txt"))]

    if udp:
        jobs.append(("nmap-udp",
                     ["nmap", "-sU", "-Pn", "--top-ports", str(CONFIG.get("udp_top_ports", "20")),
                      timing, "-oX", p("nmap_udp.xml"), host],
                     p("nmap_udp.txt")))

    if deep:
        # extra nmap pass with the known-CVE vuln scripts, on the open ports
        if rows:
            pl = ",".join(r["port"] for r in rows)
            jobs.append(("nmap-vuln",
                         ["nmap", "-sV", "--script", "vuln", "-Pn", "-p", pl, timing, host],
                         p("nmap_vuln.txt")))
        # SMB box -> netexec enumerates shares/users/null-session (read-only)
        if _smb_present(rows):
            jobs.append(("netexec-smb", ["netexec", "smb", host], p("netexec_smb.txt")))
        # web target -> fingerprint + dir brute + quick issues + optional vhosts
        if _web_present(t, rows):
            url = t["display"] if "://" in t["display"] else "http://" + t["display"]
            jobs.append(("whatweb", ["whatweb", "-a", "3", url], p("whatweb.txt")))
            jobs.append(("nikto", ["nikto", "-h", url, "-maxtime", "120s"], p("nikto.txt")))
            dc = _dir_cmd(url, p("dirscan.txt"))
            if dc:
                jobs.append((dc[0], dc[1], p("dirscan.txt")))
            vhost = CONFIG.get("vhost_domain", "").strip()
            if vhost and WORDLIST and shutil.which("ffuf"):
                jobs.append(("ffuf-vhost",
                             ["ffuf", "-u", url, "-H", f"Host: FUZZ.{vhost}",
                              "-w", WORDLIST, "-ac", "-s"],
                             p("vhosts.txt")))
    return jobs

def _auth_gate(host, extra=""):
    print(f"  {C.Y}Authorization check.{C.X} This runs real scans against {C.W}{host}{C.X}.{extra}")
    print(f"  {C.DIM}Only continue on targets you are explicitly allowed to test")
    print(f"  (for a CTF, the organizers' assigned range). Anything else is on you.{C.X}")
    return input(f"\n  Proceed? [{C.G}y{C.X}/{C.R}N{C.X}] ").strip().lower() == "y"

def _consolidate_scan(scan_dir):
    """Fold the raw per-tool text outputs into one details.txt and drop the
    intermediate files, leaving a tidy folder: summary.md + nmap.xml + details.txt.
    Run this AFTER _scan_summary (which still needs searchsploit.txt / the XMLs)."""
    keep_as_is = {"summary.md", "details.txt", "nmap.xml"}
    drop = {"nmap_ports.txt"}
    parts = []
    try:
        names = sorted(os.listdir(scan_dir))
    except OSError:
        return
    for fn in names:
        fp = os.path.join(scan_dir, fn)
        if not os.path.isfile(fp) or fn in keep_as_is:
            continue
        if fn in drop or fn.endswith(".xml"):      # intermediate nmap_ports/nmap_udp XML
            try: os.remove(fp)
            except OSError: pass
            continue
        try:                                       # a tool text output -> fold in
            body = open(fp, encoding="utf-8", errors="replace").read()
            parts.append(f"\n===== {fn} =====\n{body}")
            os.remove(fp)
        except OSError:
            pass
    if parts:
        try:
            with open(os.path.join(scan_dir, "details.txt"), "w", encoding="utf-8") as f:
                f.write("".join(parts).lstrip("\n"))
        except OSError:
            pass

def _recon_core(t, deep=False, udp=False):
    """Two-stage nmap + searchsploit (plus opt-in UDP / web enum) for one target,
    into a dedicated per-scan folder. Prints the important findings to the
    terminal and writes summary.md. No prompts. Returns the scan folder path."""
    base = _safe(t["display"]); tsd = _ts()
    scan_dir = os.path.join(RESULTS_DIR, f"{base}_{tsd}")
    os.makedirs(scan_dir, exist_ok=True)
    t.setdefault("results", [])

    def keep(fp):
        if os.path.exists(fp) and fp not in t["results"]:
            t["results"].append(fp)

    nmap_xml, ports = _run_nmap(t, scan_dir)
    rows = _parse_nmap_xml(nmap_xml)
    if ports or udp:
        for label, cmd, outpath in _extra_jobs(t, scan_dir, nmap_xml, rows, deep=deep, udp=udp):
            if label == "searchsploit" and not ports:
                continue
            print(f"  {C.B}running {label}...{C.X}")
            print(f"    {_run_tool(cmd, outpath)}")
    udp_rows = _parse_nmap_xml(os.path.join(scan_dir, "nmap_udp.xml")) if udp else []
    _scan_summary(t, nmap_xml, scan_dir, udp_rows=udp_rows)
    if CONFIG.get("keep_raw_files"):
        for fn in sorted(os.listdir(scan_dir)):
            keep(os.path.join(scan_dir, fn))
    else:
        _consolidate_scan(scan_dir)
        for fn in ("summary.md", "nmap.xml", "details.txt"):
            keep(os.path.join(scan_dir, fn))
    if ports or udp_rows:
        t["status"] = "scanned" if t.get("status", "todo") == "todo" else t.get("status")
    return scan_dir

def run_recon(t):
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}RUN RECON{C.X}  ->  {C.W}{t['display']}{C.X}  {C.DIM}({t['kind']}){C.X}\n")
    if not _auth_gate(t["host"]):
        print(f"  {C.DIM}cancelled.{C.X}"); pause(); return
    print()
    scan_dir = _recon_core(t)
    _save(TARGETS_FILE, _targets_with(t))
    print(f"\n  {C.G}Results saved under:{C.X} {C.CY}{scan_dir}{C.X}")
    _post_scan_actions(t)
    _save(TARGETS_FILE, _targets_with(t))
    pause()

def full_scan_target(t, deep=False):
    """One keypress deep scan: recon plus the top UDP ports and, on a web target,
    the heavier web enum tools."""
    clear(); header()
    kind = "UDP + web enum" if deep else "recon"
    print(f"\n  {C.BOLD}{C.W}{'DEEP SCAN' if deep else 'FULL SCAN'}{C.X}  ->  {C.W}{t['display']}{C.X}  {C.DIM}({kind}){C.X}\n")
    if not _auth_gate(t["host"]):
        print(f"  {C.DIM}cancelled.{C.X}"); pause(); return
    print()
    scan_dir = _recon_core(t, deep=deep, udp=deep)
    _save(TARGETS_FILE, _targets_with(t))
    print(f"\n  {C.G}Done. Results under:{C.X} {C.CY}{scan_dir}{C.X}")
    _post_scan_actions(t)
    _save(TARGETS_FILE, _targets_with(t))
    pause()

def scan_all():
    """One keypress from the menu: full scan every target, then report + flag hunt."""
    clear(); header()
    targets = _load(TARGETS_FILE)
    print(f"\n  {C.BOLD}{C.W}SCAN ALL TARGETS{C.X}  {C.DIM}(light recon, every target){C.X}\n")
    if not targets:
        print(f"  {C.DIM}no targets yet. Add some in the Targets screen first.{C.X}")
        pause(); return
    for i, t in enumerate(targets):
        print(f"  {C.W}{i}{C.X} {t['display']} {C.DIM}({t['kind']}){C.X}")
    hosts = ", ".join(t["host"] for t in targets)
    print()
    if not _auth_gate(f"{len(targets)} target(s)", extra=f"\n  {C.DIM}Hosts: {hosts}{C.X}"):
        print(f"  {C.DIM}cancelled.{C.X}"); pause(); return
    for t in targets:
        print(f"\n  {C.BOLD}{C.CY}== {t['display']} =={C.X}")
        _recon_core(t)
    _save(TARGETS_FILE, targets)
    path = _write_report()
    print(f"\n  {C.G}All done. Combined report:{C.X} {C.CY}{path}{C.X}")
    pause()


def _hosts_text():
    try:
        return open("/etc/hosts", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""

def _add_hosts(ip, names):
    """Append 'ip name1 name2' to /etc/hosts via sudo tee (skips names already there)."""
    have = _hosts_text().split()
    missing = [n for n in names if n not in have]
    if not missing:
        print(f"  {C.DIM}already in /etc/hosts.{C.X}"); return
    line = f"{ip} " + " ".join(missing) + "\n"
    if shutil.which("sudo") is None:
        print(f"  {C.DIM}no sudo. Add by hand:{C.X} {C.W}{line.strip()}{C.X}"); return
    try:
        p = subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input=line.encode(),
                           stdout=subprocess.DEVNULL, timeout=60)
        if p.returncode == 0:
            print(f"  {C.G}added to /etc/hosts:{C.X} {C.W}{line.strip()}{C.X}")
        else:
            print(f"  {C.R}failed (rc={p.returncode}). Add by hand:{C.X} {line.strip()}")
    except Exception as e:
        print(f"  {C.R}could not write /etc/hosts: {e}{C.X}")

def _post_scan_actions(t):
    """One optional prompt after an interactive scan: add discovered hostnames to
    /etc/hosts, or copy a numbered next-step command. Enter skips. Not used in
    scan-all (that stays promptless)."""
    names = [n for n in (t.get("hostnames") or []) if n not in _hosts_text().split()]
    steps = t.get("next_steps") or []
    opts = []
    if names:
        opts.append(f"{C.G}[h]{C.X} add {len(names)} hostname(s) to /etc/hosts")
    if steps:
        opts.append(f"{C.G}[0-{len(steps)-1}]{C.X} copy a next-step command")
    if not opts:
        return
    print(f"\n  {' '.join(opts)}   {C.DIM}[enter] done{C.X}")
    ch = input("  > ").strip().lower()
    if ch == "h" and names:
        _add_hosts(t["host"], names)
        pause()
    elif ch.isdigit() and 0 <= int(ch) < len(steps):
        tool = _clip(steps[int(ch)][1])
        if tool:
            print(f"  {C.G}copied:{C.X} {steps[int(ch)][1]}")
        else:
            print(f"  {C.DIM}no clipboard tool (apt install xclip). cmd:{C.X} {steps[int(ch)][1]}")
        pause()

def _write_box_report(t):
    """One combined markdown per target: ports, script findings, loot, results."""
    path = os.path.join(_STATE, f"writeup_{_safe(t['display'])}.md")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# {t['display']}  ({t.get('status','todo')})\n\n")
            f.write(f"Host: {t['host']}  |  kind: {t['kind']}  |  owner: {t.get('owner','-')}\n\n")
            if t.get("services"):
                f.write("## Open services\n\n")
                for s in t["services"]:
                    f.write(f"- {s}\n")
                f.write("\n")
            if t.get("script_findings"):
                f.write("## nmap script findings\n\n")
                for ln in t["script_findings"]:
                    f.write(f"- {ln}\n")
                f.write("\n")
            if t.get("hostnames"):
                f.write("## Hostnames\n\n")
                f.write(f"- `{t['host']} {' '.join(t['hostnames'])}`\n\n")
            if t.get("loot"):
                f.write("## Loot / notes\n\n")
                for n in t["loot"]:
                    f.write(f"- {n}\n")
                f.write("\n")
            if t.get("results"):
                f.write("## Result files\n\n")
                for r in t["results"]:
                    f.write(f"- `{os.path.relpath(r, _STATE)}`\n")
        return path
    except Exception as e:
        return f"(error: {e})"

def _targets_with(updated):
    targets = _load(TARGETS_FILE)
    for i, t in enumerate(targets):
        if t.get("display") == updated.get("display") and t.get("host") == updated.get("host"):
            targets[i] = updated
            return targets
    targets.append(updated)
    return targets

SEC_HEADERS = [
    ("content-security-policy", "missing_csp", "Content-Security-Policy"),
    ("strict-transport-security", "missing_hdrs", "Strict-Transport-Security"),
    ("x-frame-options", "missing_hdrs", "X-Frame-Options (clickjacking)"),
    ("x-content-type-options", "missing_hdrs", "X-Content-Type-Options (MIME sniffing)"),
    ("referrer-policy", "missing_hdrs", "Referrer-Policy"),
]
SENSITIVE_PATHS = [
    ("robots.txt", None), ("sitemap.xml", None),
    (".git/HEAD", "exposed_git"), (".env", "exposed_env"),
    ("server-status", None), ("backup.zip", None),
    (".DS_Store", None), ("admin/", "default_admin"), ("login", None),
]




# ----------------------------------------------------------------------
# report
# ----------------------------------------------------------------------
def _write_report():
    targets = _load(TARGETS_FILE)
    path = os.path.join(_STATE, f"poly_report_{_ts()}.md")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# {CONFIG['name']} scan report\n\n")
            f.write(f"_Generated {datetime.datetime.now().isoformat(timespec='seconds')}_\n\n")
            f.write("## Targets\n\n")
            if not targets:
                f.write("_none_\n\n")
            else:
                for t in targets:
                    portstr = f":{t['port']}" if t.get("port") else ""
                    f.write(f"### {t['display']}  ({t['kind']}, {t['host']}{portstr})\n\n")
                    f.write(f"- status: {t.get('status','todo')}\n")
                    f.write(f"- owner: {t.get('owner','-')}\n")
                    if t.get("services"):
                        f.write("- open services:\n")
                        for s in t["services"]:
                            f.write(f"  - {s}\n")
                    if t.get("loot"):
                        f.write("- loot / notes:\n")
                        for note in t["loot"]:
                            f.write(f"  - {note}\n")
                    if t.get("results"):
                        f.write("- result files:\n")
                        for r in t["results"]:
                            f.write(f"  - `{r}`\n")
                    f.write("\n")
    except Exception as e:
        return f"(could not write report: {e})"
    return path

# ----------------------------------------------------------------------
# screens
# ----------------------------------------------------------------------




def screen_links():
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}QUICK LINKS{C.X}  {C.DIM}(bookmark these on every machine){C.X}\n")
    for name, url in LINKS:
        print(f"  {C.G}{name:<28}{C.X} {C.CY}{url}{C.X}")
    pause()

def screen_advisor():
    while True:
        clear(); header()
        print(f"\n  {C.BOLD}{C.W}WHAT TOOL DO I USE?{C.X}  {C.DIM}(pick what you're looking at){C.X}\n")
        for n, (label, _) in enumerate(ADVISOR):
            print(f"   {C.G}[{n}]{C.X} {label}")
        print(f"   {C.DIM}[b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        if ch.isdigit() and 0 <= int(ch) < len(ADVISOR):
            label, lines = ADVISOR[int(ch)]
            clear(); header()
            print(f"\n  {C.BOLD}{C.W}{label}{C.X}\n")
            for ln in lines:
                print(f"    {C.DIM}-{C.X} {ln}")
            print(f"\n  {C.DIM}Full commands per category: menu [c] cheat sheet.{C.X}")
            pause()


STATUS_ORDER = ["todo", "scanned", "foothold", "rooted"]

def _status_badge(t):
    st = t.get("status", "todo")
    col = {"todo": C.DIM, "scanned": C.CY, "foothold": C.Y, "rooted": C.G}.get(st, C.DIM)
    return f"{col}{st:<8}{C.X}"

def screen_targets():
    while True:
        clear(); header()
        targets = _load(TARGETS_FILE)
        print(f"\n  {C.BOLD}{C.W}TARGETS{C.X}  {C.DIM}(accepts an IP, host:port, or a link){C.X}\n")
        if not targets:
            print(f"  {C.DIM}no targets yet. [a] to add one.{C.X}")
        else:
            for i, t in enumerate(targets):
                tag = f"{C.CY}web{C.X}" if t["kind"] == "web" else f"{C.G}host{C.X}"
                portstr = f":{t['port']}" if t.get("port") else ""
                nres = len(t.get("results", []))
                rtag = f"  {C.DIM}{nres} result(s){C.X}" if nres else ""
                print(f"  {C.W}{i}{C.X} {_status_badge(t)} [{tag}] {C.W}{t['display']}{C.X}  "
                      f"{C.DIM}{t['host']}{portstr}  owner:{t.get('owner','-')}{C.X}{rtag}")
        print(f"\n  {C.DIM}[a] add   [r] recon   [e] deep (UDP+web enum)   "
              f"[v] view/loot   [m] mark status   [o] owner   [d] delete   [b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        elif ch == "a":
            raw = input("  target (IP, host:port, or https://... link): ").strip()
            parsed = classify_target(raw)
            if not parsed:
                continue
            owner = input("  owner (optional): ").strip()
            parsed["owner"] = owner or "-"
            parsed["status"] = "todo"
            targets.append(parsed)
            _save(TARGETS_FILE, targets)
        elif ch == "e":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                full_scan_target(targets[int(idx)], deep=True)
        elif ch == "r":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                run_recon(targets[int(idx)])
        elif ch == "v":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                _view_target(targets[int(idx)])
        elif ch == "m":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                st = input(f"  status [{' / '.join(STATUS_ORDER)}]: ").strip().lower()
                if st in STATUS_ORDER:
                    targets[int(idx)]["status"] = st
                    _save(TARGETS_FILE, targets)
        elif ch == "o":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                targets[int(idx)]["owner"] = input("  owner: ").strip() or "-"
                _save(TARGETS_FILE, targets)
        elif ch == "d":
            idx = input("  row number: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(targets):
                targets.pop(int(idx))
                _save(TARGETS_FILE, targets)

def _view_target(t):
    while True:
        clear(); header()
        portstr = f":{t['port']}" if t.get("port") else ""
        print(f"\n  {C.BOLD}{C.W}{t['display']}{C.X}   {_status_badge(t)}")
        print(f"  {C.DIM}parsed as{C.X} {C.G}{t['kind']}{C.X}  "
              f"{C.DIM}host={C.X}{t['host']}{portstr}"
              + (f"  {C.DIM}path={C.X}{t['path']}" if t.get('path') else ""))
        if t.get("services"):
            print(f"\n  {C.Y}Open services (last scan){C.X}")
            for s in t["services"]:
                print(f"    {C.DIM}-{C.X} {s}")
        loot = t.get("loot", [])
        print(f"\n  {C.Y}Loot / notes{C.X}  {C.DIM}(creds, hashes, paths, anything you find){C.X}")
        if not loot:
            print(f"    {C.DIM}none yet. [l] to add.{C.X}")
        else:
            for i, note in enumerate(loot):
                print(f"    {C.G}{i}{C.X} {note}")
        method = WEB_METHOD if t["kind"] == "web" else HOST_METHOD
        label = "WEB APP - manual methodology" if t["kind"] == "web" else "NETWORK HOST - manual methodology"
        print(f"\n  {C.Y}{label}{C.X}  {C.DIM}(the exploit tier is yours to run by hand){C.X}")
        for step in method:
            print(f"    {C.DIM}-{C.X} {step}")
        res = t.get("results", [])
        print(f"\n  {C.Y}Saved result files{C.X}")
        if not res:
            print(f"    {C.DIM}none yet. [f] or [r] on the list runs scans.{C.X}")
        else:
            for r in res:
                flag = "" if os.path.exists(r) else f"  {C.R}(missing){C.X}"
                print(f"    {C.DIM}-{C.X} {C.CY}{os.path.relpath(r, _STATE)}{C.X}{flag}")
        print(f"\n  {C.DIM}[l] add loot   [x] delete loot   [w] write box report   [b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        elif ch == "l":
            note = input("  loot (cred / hash / path / finding): ").strip()
            if note:
                t.setdefault("loot", []).append(note)
                _save(TARGETS_FILE, _targets_with(t))
        elif ch == "x":
            idx = input("  loot row to delete: ").strip()
            if idx.isdigit() and 0 <= int(idx) < len(t.get("loot", [])):
                t["loot"].pop(int(idx))
                _save(TARGETS_FILE, _targets_with(t))
        elif ch == "w":
            path = _write_box_report(t)
            print(f"\n  {C.G}Wrote box report:{C.X} {C.CY}{path}{C.X}")
            pause()

def write_setup():
    clear(); header()
    path = os.path.join(_HERE, "setup.sh")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(SETUP_SCRIPT)
        os.chmod(path, 0o755)
        print(f"\n  {C.G}Wrote role-aware setup script to:{C.X} {path}")
        print(f"  Run it on any machine:  {C.CY}bash setup.sh{C.X}")
        print(f"  {C.DIM}Installs standard free tooling via apt or pacman. Review it before running.{C.X}")
    except Exception as e:
        print(f"\n  {C.R}could not write setup.sh: {e}{C.X}")
    pause()

# the binaries Poly actually invokes, in the order they matter
TOOL_AUDIT = [
    ("nmap", "nmap"), ("searchsploit", "searchsploit"),
    ("feroxbuster", "feroxbuster"), ("ffuf", "ffuf"), ("gobuster", "gobuster"),
    ("whatweb", "whatweb"), ("nikto", "nikto"),
    ("netexec", "netexec"), ("enum4linux-ng", "enum4linux-ng"),
    ("sqlmap", "sqlmap"), ("snmpwalk", "snmpwalk"),
    ("hydra", "hydra"), ("john", "john"), ("xclip (arsenal copy)", "xclip"),
]

def _missing_tools():
    return [(label, b) for label, b in TOOL_AUDIT if shutil.which(b) is None]

def install_tools():
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}TOOL CHECK / INSTALL{C.X}  {C.DIM}(what Poly uses){C.X}\n")
    missing = []
    for label, b in TOOL_AUDIT:
        ok = shutil.which(b) is not None
        mark = f"{C.G}[ok]{C.X}  " if ok else f"{C.R}[--]{C.X}  "
        print(f"    {mark}{label}")
        if not ok:
            missing.append(label)
    if not missing:
        print(f"\n  {C.G}All set - everything Poly uses is installed.{C.X}")
        pause(); return
    print(f"\n  {C.Y}Missing ({len(missing)}):{C.X} {', '.join(missing)}")
    print(f"  {C.DIM}Poly will write setup.sh next to itself and run it (apt + pipx).")
    print(f"  apt will ask for your sudo password. To read it first: menu [m] -> Write setup.sh.{C.X}")
    if input(f"\n  Install the missing tools now? [{C.G}y{C.X}/{C.R}N{C.X}] ").strip().lower() != "y":
        print(f"  {C.DIM}skipped.{C.X}"); pause(); return
    path = os.path.join(_HERE, "setup.sh")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(SETUP_SCRIPT)
        os.chmod(path, 0o755)
    except Exception as e:
        print(f"  {C.R}could not write setup.sh: {e}{C.X}"); pause(); return
    print(f"\n  {C.B}running {C.CY}{path}{C.X}{C.B} ...{C.X}  {C.DIM}(this can take a few minutes){C.X}\n")
    try:
        subprocess.run(["bash", path], timeout=3600)   # inherits the terminal -> live output + sudo prompt
    except KeyboardInterrupt:
        print(f"\n  {C.Y}install interrupted.{C.X}")
    except Exception as e:
        print(f"\n  {C.R}install error: {e}{C.X}")
    still = [l for l, _ in _missing_tools()]
    if still:
        print(f"\n  {C.Y}Still missing:{C.X} {', '.join(still)}  {C.DIM}(install those by hand){C.X}")
    else:
        print(f"\n  {C.G}Done - everything Poly uses is now installed.{C.X}")
    pause()

def export_report():
    clear(); header()
    path = _write_report()
    print(f"\n  {C.G}Wrote session report to:{C.X} {C.CY}{path}{C.X}")
    pause()


def screen_search():
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}SEARCH RESULTS{C.X}  {C.DIM}({RESULTS_DIR}){C.X}\n")
    kw = input("  keyword (regex ok): ").strip()
    if not kw:
        return
    try:
        rx = re.compile(kw, re.IGNORECASE)
    except re.error:
        rx = re.compile(re.escape(kw), re.IGNORECASE)
    hits = 0
    for fp in _iter_result_files():
        rel = os.path.relpath(fp, RESULTS_DIR)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    if rx.search(line):
                        hits += 1
                        print(f"  {C.CY}{rel}:{n}{C.X}  {line.strip()[:120]}")
        except Exception:
            pass
    if not hits:
        print(f"  {C.DIM}no matches.{C.X}")
    pause()

def screen_cheatsheet():
    path = os.path.join(_HERE, "CHEATSHEET.md")
    if not os.path.exists(path):
        clear(); header()
        print(f"\n  {C.DIM}CHEATSHEET.md not found next to poly.py. Keep them in the same folder.{C.X}")
        pause(); return
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception as e:
        clear(); header(); print(f"\n  {C.R}could not read: {e}{C.X}"); pause(); return
    secs = [(i, ln[3:].strip()) for i, ln in enumerate(lines) if ln.startswith("## ")]
    while True:
        clear(); header()
        print(f"\n  {C.BOLD}{C.W}CHEAT SHEET{C.X}  {C.DIM}(offline){C.X}\n")
        for n, (i, title) in enumerate(secs):
            print(f"   {C.G}[{n}]{C.X} {title}")
        print(f"   {C.DIM}[b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        if ch.isdigit() and 0 <= int(ch) < len(secs):
            start = secs[int(ch)][0]
            end = secs[int(ch) + 1][0] if int(ch) + 1 < len(secs) else len(lines)
            clear(); header(); print()
            for ln in lines[start:end]:
                print("  " + ln)
            pause()

# ----------------------------------------------------------------------
# arsenal: find your wordlists + payload/reference repos on a messy box
# (Poly indexes what is already installed and hands you the path - it does
#  not embed lists or auto-fire anything. Methodology, not automation.)
# ----------------------------------------------------------------------

# roots checked by direct path join (cheap) when resolving a known list
_RESOLVE_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share",                      # seclists/SecLists live here on Kali
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/dirbuster",
    "/usr/share/wfuzz/wordlist",
    "/opt",
    os.path.expanduser("~"),
    os.path.expanduser("~/wordlists"),
    os.path.expanduser("~/tools"),
]

# the handful you actually type into gobuster/ffuf/hydra/john, by job.
# each entry: (label, [candidate suffixes, tried against every resolve root])
KEY_WORDLISTS = [
    ("dir brute - small/fast", ["dirb/common.txt",
        "seclists/Discovery/Web-Content/common.txt",
        "SecLists/Discovery/Web-Content/common.txt"]),
    ("dir brute - medium", ["dirbuster/directory-list-2.3-medium.txt",
        "seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"]),
    ("dir brute - raft dirs", ["seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "SecLists/Discovery/Web-Content/raft-medium-directories.txt"]),
    ("files - raft files", ["seclists/Discovery/Web-Content/raft-medium-files.txt",
        "SecLists/Discovery/Web-Content/raft-medium-files.txt"]),
    ("passwords - rockyou", ["rockyou.txt", "rockyou.txt.gz"]),
    ("passwords - top 10k", ["seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        "SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"]),
    ("usernames", ["seclists/Usernames/top-usernames-shortlist.txt",
        "SecLists/Usernames/top-usernames-shortlist.txt",
        "metasploit/unix_users.txt"]),
    ("subdomains (DNS)", ["seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "SecLists/Discovery/DNS/subdomains-top1million-5000.txt"]),
    ("LFI payloads", ["seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"]),
    ("SQLi fuzz", ["seclists/Fuzzing/SQLi/Generic-SQLi.txt",
        "SecLists/Fuzzing/SQLi/Generic-SQLi.txt"]),
]

# payload / reference material to LOCATE (open it yourself - never auto-run)
PAYLOAD_REPOS = [
    ("PayloadsAllTheThings", ["PayloadsAllTheThings", "payloadsallthethings"]),
    ("SecLists (root)",      ["seclists", "SecLists"]),
    ("webshells (stock Kali)", ["webshells"]),
    ("Nishang (PowerShell)", ["nishang", "Nishang"]),
    ("wordlists (root)",     ["wordlists"]),
]

_WALK_SKIP = {"node_modules", ".git", ".cache", ".cargo", ".rustup", ".m2",
              ".gradle", ".npm", "AppData", "__pycache__", ".vscode", "OneDrive"}

def _human(n):
    for u in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}T"

def _first_existing(cands, want_dir=False):
    for c in cands:
        if (os.path.isdir(c) if want_dir else os.path.exists(c)):
            return c
    return None

def _resolve_wordlist(suffixes):
    cands = []
    for s in suffixes:
        if s.startswith("/"):
            cands.append(s)
        else:
            cands += [os.path.join(r, s) for r in _RESOLVE_ROOTS]
    return _first_existing(cands)

def _find_repo(names):
    bases = ["/usr/share", "/opt", os.path.expanduser("~"),
             "/usr/share/wordlists", os.path.expanduser("~/tools")]
    cands = [os.path.join(b, nm) for b in bases for nm in names]
    return _first_existing(cands, want_dir=True)

def _clip(text):
    for tool in (["xclip", "-selection", "clipboard"], ["xsel", "-ib"], ["wl-copy"]):
        if shutil.which(tool[0]):
            try:
                subprocess.run(tool, input=text.encode(), timeout=5)
                return tool[0]
            except Exception:
                pass
    return None

def _arsenal_find(kw, limit=40):
    kw = kw.lower()
    roots, seen = [], set()
    for r in ["/usr/share/wordlists", "/usr/share/seclists", "/usr/share/SecLists",
              "/opt", os.path.expanduser("~/wordlists"),
              os.path.expanduser("~/tools"), os.path.expanduser("~")]:
        rp = os.path.realpath(r)
        if os.path.isdir(r) and rp not in seen:
            seen.add(rp); roots.append(r)
    hits, scanned = [], 0
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _WALK_SKIP and not d.startswith(".")]
            scanned += 1
            if scanned > 6000:
                break
            for f in files:
                if kw in f.lower():
                    hits.append(os.path.join(dirpath, f))
                    if len(hits) >= limit:
                        break
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}wordlists matching '{kw}'{C.X}\n")
    if not hits:
        print(f"  {C.DIM}nothing found under the usual roots.{C.X}")
    for h in hits:
        sz = _human(os.path.getsize(h)) if os.path.isfile(h) else "-"
        print(f"   {C.W}{h}{C.X} {C.DIM}({sz}){C.X}")
    if len(hits) >= limit:
        print(f"\n  {C.DIM}(stopped at {limit} - narrow the keyword){C.X}")
    pause()

def screen_arsenal():
    while True:
        clear(); header()
        print(f"\n  {C.BOLD}{C.W}ARSENAL{C.X}  {C.DIM}(your wordlists + payload refs, located on this box){C.X}\n")
        found = []
        print(f"  {C.BOLD}wordlists you plug into gobuster / ffuf / hydra / john:{C.X}")
        for n, (label, suffixes) in enumerate(KEY_WORDLISTS):
            path = _resolve_wordlist(suffixes)
            found.append(path)
            if path:
                sz = _human(os.path.getsize(path)) if os.path.isfile(path) else "-"
                note = f" {C.R}(gunzip it){C.X}" if path.endswith(".gz") else ""
                print(f"   {C.G}[{n}]{C.X} {label:<22} {C.W}{path}{C.X} {C.DIM}({sz}){C.X}{note}")
            else:
                print(f"   {C.DIM}[{n}] {label:<22} not found{C.X}")
        print(f"\n  {C.BOLD}payload & reference repos  {C.DIM}(open these, don't auto-fire):{C.X}")
        for label, names in PAYLOAD_REPOS:
            path = _find_repo(names)
            if path:
                print(f"   {C.CY}>{C.X} {label:<24} {C.W}{path}{C.X}")
            else:
                print(f"   {C.DIM}  {label:<24} not installed{C.X}")
        print(f"\n  {C.DIM}exploit refs: menu [c] cheat sheet, and PayloadsAllTheThings / HackTricks / GTFOBins.{C.X}")
        print(f"  {C.DIM}[#] copy that path to clipboard   [f] find a wordlist by name   [b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        if ch == "f":
            kw = input("  name contains: ").strip()
            if kw:
                _arsenal_find(kw)
            continue
        if ch.isdigit() and 0 <= int(ch) < len(found) and found[int(ch)]:
            tool = _clip(found[int(ch)])
            if tool:
                print(f"  {C.G}copied ({tool}):{C.X} {found[int(ch)]}")
            else:
                print(f"  {C.DIM}no clipboard tool (apt install xclip). path:{C.X} {found[int(ch)]}")
            pause()

# ----------------------------------------------------------------------
# "more" - prep + reference you set up once and rarely touch mid-box
# ----------------------------------------------------------------------
MORE = [
    ("Install / check tools", install_tools),
    ("Write setup.sh", write_setup),
    ("Quick links", screen_links),
    ("Export scan report", export_report),
]

def screen_more():
    while True:
        clear(); header()
        print(f"\n  {C.BOLD}{C.W}MORE{C.X}  {C.DIM}(setup + reference - rarely needed mid-box){C.X}\n")
        for n, (label, _) in enumerate(MORE):
            print(f"   {C.G}[{n}]{C.X} {label}")
        print(f"   {C.DIM}[b] back{C.X}")
        ch = input("  > ").strip().lower()
        if ch == "b":
            return
        if ch.isdigit() and 0 <= int(ch) < len(MORE):
            MORE[int(ch)][1]()

# ----------------------------------------------------------------------
# main loop  -  lean, active-use menu; the rest lives under [m] More
# ----------------------------------------------------------------------
MENU = [
    ("1", "Targets (scan an IP or URL)", screen_targets),
    ("s", "Scan all targets now", scan_all),
    ("w", "Arsenal: wordlists + payload refs", screen_arsenal),
    ("t", "What tool do I use?", screen_advisor),
    ("k", "Search results for a keyword", screen_search),
    ("c", "Cheat sheet (offline)", screen_cheatsheet),
    ("m", "More (setup + reference)", screen_more),
]

def _quick_target(raw):
    """Paste-and-go: classify a pasted IP / host:port / URL, add it to the board,
    and run the default scan straight away (recon)."""
    parsed = classify_target(raw)

    def _looks_like_target(p):
        if not p or not p.get("host"):
            return False
        if "://" in raw or "/" in raw or "." in p["host"]:
            return True
        try:
            ipaddress.ip_address(p["host"]); return True
        except ValueError:
            pass
        return bool(p.get("port"))

    if not _looks_like_target(parsed):
        print(f"  {C.DIM}'{raw}' isn't a menu option or a target.")
        print(f"  Paste an IP, host:port, or http(s):// URL to scan it now.{C.X}")
        pause(); return
    targets = _load(TARGETS_FILE)
    existing = next((t for t in targets
                     if t.get("display") == parsed["display"] and t.get("host") == parsed["host"]), None)
    t = existing or parsed
    if not existing:
        t.setdefault("owner", "-"); t.setdefault("status", "todo")
    clear(); header()
    print(f"\n  {C.BOLD}{C.W}QUICK SCAN{C.X}  ->  {C.W}{t['display']}{C.X}  {C.DIM}({t['kind']}){C.X}\n")
    if not _auth_gate(t["host"]):
        print(f"  {C.DIM}cancelled.{C.X}"); pause(); return
    print()
    scan_dir = _recon_core(t)
    _save(TARGETS_FILE, _targets_with(t))
    print(f"\n  {C.G}Done. Results under:{C.X} {C.CY}{scan_dir}{C.X}")
    print(f"  {C.DIM}Saved to the board - open [1] for a deep scan ([e]), loot, or status.{C.X}")
    _post_scan_actions(t)
    _save(TARGETS_FILE, _targets_with(t))
    pause()

def main():
    if "--check" in sys.argv:
        header()
        for _, _, fn in MENU:
            assert callable(fn)
        for fn in (run_recon, _run_nmap, _extra_jobs, _open_ports,
                   full_scan_target, scan_all, _recon_core, _write_report,
                   _iter_result_files, _parse_nmap_xml, _scan_summary,
                   _top_cves, screen_cheatsheet, screen_search,
                   screen_arsenal, _resolve_wordlist, _find_repo, _arsenal_find, _clip,
                   screen_more, _dir_cmd, _web_present, _smb_present, _status_badge,
                   _quick_target, install_tools, _parse_scripts, _script_findings,
                   _hostnames_from_scripts, _hosts_text, _add_hosts, _post_scan_actions,
                   _write_box_report, screen_advisor, screen_links, screen_targets,
                   write_setup, export_report, _consolidate_scan, _view_target,
                   _targets_with, _missing_tools, _human, _first_existing,
                   _resolve_wordlist, classify_target, _safe, _ts, _load, _save):
            assert callable(fn)
        for _, fn in MORE:
            assert callable(fn)
        print("selftest ok")
        return
    keys = {key for key, _, _ in MENU}
    while True:
        clear(); header()
        print(f"\n  {C.BOLD}{C.W}MENU{C.X}   {C.DIM}(or just paste an IP / URL and press enter to scan it){C.X}\n")
        for key, label, _ in MENU:
            print(f"   {C.G}[{key}]{C.X} {label}")
        print(f"   {C.R}[0]{C.X} quit")
        raw = input(f"\n  {C.W}>{C.X} ").strip()
        choice = raw.lower()
        if choice == "0":
            clear()
            print(f"{C.BR}stay sharp.{C.X}\n")
            return
        if choice in keys:
            for key, _, fn in MENU:
                if choice == key:
                    fn()
                    break
        elif raw:
            _quick_target(raw)

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{C.BR}bye.{C.X}")
