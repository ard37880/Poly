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
import sys
import json
import shutil
import socket
import datetime
import tempfile
import ipaddress
import urllib.parse
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
# Tool setup for Poly. Detects apt, pacman or Homebrew.
# Each package is installed on its own, so one name your distro does not carry
# cannot stop the rest from installing. Whatever failed is listed at the end.
# Usage:  bash setup.sh
FAILED=""
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  inst() { sudo apt-get install -y "$1" >/dev/null 2>&1; }
  CORE="nmap curl wget git python3 python3-pip python3-venv pipx file binwalk libimage-exiftool-perl steghide foremost gdb radare2"
  WEB="feroxbuster ffuf gobuster dirb sqlmap whatweb nikto recon-ng exploitdb seclists enum4linux-ng"
  NET="netexec smbclient smbmap snmp hydra john xclip chisel ligolo-ng"
elif command -v pacman >/dev/null 2>&1; then
  inst() { sudo pacman -S --needed --noconfirm "$1" >/dev/null 2>&1; }
  CORE="nmap curl wget git python python-pip python-pipx file binwalk perl-image-exiftool gdb radare2"
  WEB="feroxbuster ffuf gobuster sqlmap nikto"
  NET="smbclient net-snmp hydra john xclip"
elif command -v brew >/dev/null 2>&1; then
  inst() { brew install "$1" >/dev/null 2>&1; }
  CORE="nmap curl wget git python pipx binwalk exiftool radare2"
  WEB="feroxbuster ffuf gobuster sqlmap nikto whatweb exploitdb"
  NET="net-snmp hydra john-jumbo"
else
  echo "No apt, pacman or brew found. Install tools by hand."; exit 1
fi

try_all() {
  for p in "$@"; do
    printf '  %-24s' "$p"
    if inst "$p"; then echo ok; else echo "not available here"; FAILED="$FAILED $p"; fi
  done
}

echo "[*] Core triage";  try_all $CORE
echo "[*] Web + recon";  try_all $WEB
echo "[*] SMB / AD + pivoting"; try_all $NET

# netexec and enum4linux-ng are only packaged on Kali/Parrot; pipx gets them anywhere
if command -v pipx >/dev/null 2>&1; then
  command -v netexec >/dev/null 2>&1 || pipx install git+https://github.com/Pennyw0rth/NetExec >/dev/null 2>&1 \
    || FAILED="$FAILED netexec(pipx)"
  command -v enum4linux-ng >/dev/null 2>&1 || pipx install git+https://github.com/cddmp/enum4linux-ng >/dev/null 2>&1 \
    || FAILED="$FAILED enum4linux-ng(pipx)"
  command -v vol >/dev/null 2>&1 || pipx install volatility3 >/dev/null 2>&1 || FAILED="$FAILED volatility3(pipx)"
fi

# CTF python libs go in their own venv: modern distros refuse system-wide pip
# installs (PEP 668), and forcing it can break the system python
echo "[*] Python libs -> ~/.venvs/ctf"
if python3 -m venv "$HOME/.venvs/ctf" && "$HOME/.venvs/ctf/bin/pip" install -q pwntools pycryptodome sympy gmpy2; then
  echo "  ok. Use them with:  source ~/.venvs/ctf/bin/activate"
else
  FAILED="$FAILED python-libs"
fi

echo
if [ -n "$FAILED" ]; then
  echo "[!] Not installed:$FAILED"
  echo "    Some of these are only packaged on Kali/Parrot (or BlackArch/AUR on Arch); install those by hand."
fi
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

def _dir_cmd(url):
    """Build the directory-brute command from CONFIG['dir_tool'], falling back
    to whatever is actually installed. Returns (label, argv) or None."""
    pref = (CONFIG.get("dir_tool") or "feroxbuster").lower()
    order = [pref] + [t for t in ("feroxbuster", "ffuf", "gobuster", "dirb") if t != pref]
    tls = url.lower().startswith("https://")   # lab boxes use self-signed certs
    for tool in order:
        if shutil.which(tool) is None:
            continue
        # all of these print results to stdout; _run_tool captures that to the output file
        if tool == "feroxbuster":
            cmd = ["feroxbuster", "-u", url, "--silent", "--no-state"]
            if tls:
                cmd.append("-k")
            if WORDLIST:
                cmd += ["-w", WORDLIST]
            return ("feroxbuster", cmd)
        if tool == "ffuf" and WORDLIST:
            return ("ffuf", ["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", WORDLIST, "-ac", "-s"])
        if tool == "gobuster" and WORDLIST:
            return ("gobuster", ["gobuster", "dir", "-q", "-u", url, "-w", WORDLIST]
                    + (["-k"] if tls else []))
        if tool == "dirb":
            return ("dirb", ["dirb", url] + ([WORDLIST] if WORDLIST else []))
    return None

# ----------------------------------------------------------------------
# target input: accept an IP (optional :port) OR a link, detect + parse
# ----------------------------------------------------------------------
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$")

def _valid_host(h):
    """An IP address or a plain hostname, nothing else. This is what keeps a
    target like '--script=x.nse' or '-iL file' from reaching nmap as an option,
    including targets loaded from a shared poly_targets.json."""
    if not h or len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(h))

def _is_v6(h):
    try:
        return ipaddress.ip_address(h).version == 6
    except ValueError:
        return False

def _nmap_family(h):
    """nmap needs -6 to scan an IPv6 address."""
    return ["-6"] if _is_v6(h) else []

def _web_url(scheme, host, port=None, path="/"):
    h = f"[{host}]" if _is_v6(host) else host
    default = 443 if scheme == "https" else 80
    p = f":{port}" if port and int(port) != default else ""
    return f"{scheme}://{h}{p}{path or '/'}"

def classify_target(raw):
    """Return dict: kind ('host'|'web'), host, port, scheme, path, display.
    Returns None for anything that is not a usable IP, host[:port][/path] or
    http(s) URL."""
    s = raw.strip()
    if not s:
        return None
    if "://" in s:
        u = urllib.parse.urlparse(s)
        if u.scheme.lower() not in ("http", "https"):
            return None
        host = u.hostname or ""
        try:
            port = u.port
        except ValueError:
            return None
        if not _valid_host(host):
            return None
        return {"kind": "web", "host": host, "port": port, "scheme": u.scheme.lower(),
                "path": u.path or "/", "display": s}
    rest, slash, tail = s.partition("/")
    path = "/" + tail if slash else None
    host_part, port = rest, None
    if rest.startswith("["):                       # [v6addr] or [v6addr]:port
        end = rest.find("]")
        if end == -1:
            return None
        host_part, after = rest[1:end], rest[end + 1:]
        if after:
            if not (after.startswith(":") and after[1:].isdigit()):
                return None
            port = int(after[1:])
    elif rest.count(":") == 1:                     # host:port
        host_part, _, port_s = rest.partition(":")
        if not port_s.isdigit():
            return None
        port = int(port_s)
    # two or more colons without brackets: a bare IPv6 address, kept as-is
    if not _valid_host(host_part):
        return None
    if port is not None and not 0 < port < 65536:
        return None
    try:
        ipaddress.ip_address(host_part)
        is_ip = True
    except ValueError:
        is_ip = False
    if path is not None:
        return {"kind": "web", "host": host_part, "port": port, "scheme": "http",
                "path": path, "display": s}
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
_HTTP_FP_RE = re.compile(r"HTTP/1\\?\.[01]\\x20[1-5]\d\d")

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
                name = (svc.get("name") if svc is not None else "") or ""
                # nmap reports HTTPS as name="http" tunnel="ssl"; keep the tunnel
                # so the hints and web enum use https (matches nmap's ssl/http)
                product = (svc.get("product") if svc is not None else "") or ""
                # a service nmap could not name but that answered with an HTTP
                # status line is a web server (custom apps, new server versions)
                fp = (svc.get("servicefp") if svc is not None else "") or ""
                if name in ("", "unknown") and _HTTP_FP_RE.search(fp):
                    name = "http"
                    product = product or "(answers HTTP, nmap could not name it)"
                if name and svc.get("tunnel") == "ssl":
                    name = "ssl/" + name
                rows.append({
                    "port": port.get("portid", "?"),
                    "proto": port.get("protocol", "tcp"),
                    "service": name,
                    "product": product,
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

_DISCOVERED_RE = re.compile(r"Discovered open port (\d+)/tcp")

def _discovered_ports(txtp):
    """Open ports from nmap's -v stdout. nmap only writes the XML port list once
    the host finishes, so if the sweep is killed (timeout, ctrl-c) the XML has
    nothing in it, but the 'Discovered open port' lines are already on disk."""
    try:
        with open(txtp, encoding="utf-8", errors="replace") as f:
            found = _DISCOVERED_RE.findall(f.read())
    except OSError:
        return []
    return sorted(set(found), key=int)

def _guess_rows(ports):
    """Stand-in rows when the -sV pass did not finish: open ports from the sweep,
    with the service name guessed from the port number."""
    rows = []
    for p in ports:
        try:
            name = socket.getservbyport(int(p), "tcp")
        except (OSError, ValueError):
            name = ""
        rows.append({"port": p, "proto": "tcp", "service": name,
                     "product": "(guessed from port, -sV did not finish)", "version": ""})
    return rows

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
        url = _web_url(_http_scheme(s, port), host, port)
        wl = WORDLIST or "/usr/share/wordlists/dirb/common.txt"
        return (f"gobuster dir -u {url} -w {wl}"
                + (" -k" if url.startswith("https") else "")
                + f" ; whatweb {url} ; check /robots.txt /.git /.env")
    return None

def _http_scheme(service, port):
    s = (service or "").lower()
    return "https" if ("ssl" in s or "https" in s or str(port) in ("443", "8443")) else "http"

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
        with open(sp, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in lines:
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

def _print_problems(problems):
    if not problems:
        return
    print(f"\n  {C.BOLD}{C.Y}SCAN PROBLEMS{C.X}  {C.DIM}(results below may be incomplete){C.X}")
    for ln in problems:
        print(f"    {C.Y}!{C.X} {ln}")

def _scan_summary(t, rows, xmlp, scan_dir=None, udp_rows=None, problems=None):
    udp_rows = udp_rows or []
    problems = problems or []
    _print_problems(problems)
    if not rows and not udp_rows:
        if problems:
            print(f"\n  {C.Y}no open ports found, but the scan did not run cleanly (see above).{C.X}")
            print(f"  {C.DIM}This is not proof the host is down. Fix the problem and rescan.{C.X}")
        else:
            print(f"\n  {C.Y}no open ports parsed from the scan.{C.X}")
            print(f"  {C.DIM}if you expected some: the box may be booting, your VPN/route to it may be")
            print(f"  down, or it's fully filtered. Sanity-check reachability with:{C.X}")
            print(f"    {C.W}nmap -Pn -p22 {t['host']}{C.X}")
        if scan_dir:
            try:
                with open(os.path.join(scan_dir, "summary.md"), "w", encoding="utf-8") as f:
                    f.write(f"# {t['display']} - scan summary\n\n")
                    if problems:
                        f.write("No open ports found, but the scan did not run cleanly:\n\n")
                        for ln in problems:
                            f.write(f"- {ln}\n")
                    else:
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
    # (deduped on the command itself, so http on 80 and on 8080 both get a step)
    steps, seen = [], set()
    for r in rows + udp_rows:
        hint = _service_hint(r["service"], r["port"], host)
        if hint and hint not in seen:
            seen.add(hint); steps.append((r["service"], hint))
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
                f.write(f"Host: {host}\n\n")
                if problems:
                    f.write("## Scan problems (results may be incomplete)\n\n")
                    for ln in problems:
                        f.write(f"- {ln}\n")
                    f.write("\n")
                f.write("## Open ports\n\n")
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
# saved results
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
def _last_line(path):
    """Last meaningful line of a tool's output, to show why it failed."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [_strip_ansi(ln).strip() for ln in f]
    except OSError:
        return ""
    lines = [ln for ln in lines if ln and not ln.startswith(("$ ", "# "))]
    return lines[-1][:120] if lines else ""

# exit codes that mean "ran fine" for tools that do not just use 0
_OK_RC = {"nikto": (0, 1)}   # nikto exits 1 whenever it reports findings

def _run_tool(cmd, outpath):
    """Run one tool, output captured to outpath. Returns (state, message) where
    state is ok | failed | timeout | skipped | error, so callers can tell a
    clean run from one that died part way."""
    exe = cmd[0]
    if exe == "sudo":                      # the real tool is the first non-flag arg
        exe = next((a for a in cmd[1:] if not a.startswith("-")), "sudo")
    if shutil.which(cmd[0]) is None or shutil.which(exe) is None:
        return "skipped", f"{C.DIM}skipped ({exe} not installed){C.X}"
    try:
        with open(outpath, "w", encoding="utf-8", errors="replace") as f:
            f.write("$ " + " ".join(cmd) + "\n")
            f.write("# " + datetime.datetime.now().isoformat(timespec="seconds") + "\n\n")
            f.flush()
            # stdin from /dev/null: a tool that stops to ask a question (nikto's
            # update prompt) would otherwise hang the scan behind a log file.
            # sudo still prompts, it reads the password from the terminal itself.
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=f,
                                  stderr=subprocess.STDOUT, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        lim = f"{SCAN_TIMEOUT // 60}m" if SCAN_TIMEOUT >= 60 else f"{SCAN_TIMEOUT}s"
        return "timeout", f"{C.Y}timed out{C.X} after {lim} (partial)  ->  {C.CY}{outpath}{C.X}"
    except Exception as e:
        return "error", f"{C.R}error: {e}{C.X}"
    if proc.returncode not in _OK_RC.get(os.path.basename(exe), (0,)):
        why = _last_line(outpath)
        return "failed", (f"{C.Y}exited with rc={proc.returncode}, check the output{C.X}  ->  {C.CY}{outpath}{C.X}"
                          + (f"\n      {C.DIM}{why}{C.X}" if why else ""))
    return "ok", f"{C.G}done{C.X}  ->  {C.CY}{outpath}{C.X}"

def _run_nmap(t, scan_dir):
    """Two-stage TCP nmap: a fast full-range sweep to find open ports, then
    -sV -sC against ONLY those ports. Faster than one -sV -sC -p- and just as
    reliable. Returns (nmap_xml_path, [open ports], rows, [problems]) and
    prints progress. A stage that dies part way is reported in problems
    instead of being mistaken for a host with nothing open."""
    host = t["host"]
    fam = _nmap_family(host)
    timing = CONFIG.get("nmap_timing") or "-T4"
    stage1_xml = os.path.join(scan_dir, "nmap_ports.xml")
    stage1_txt = os.path.join(scan_dir, "nmap_ports.txt")
    nmap_xml = os.path.join(scan_dir, "nmap.xml")
    problems = []
    if shutil.which("nmap") is None:
        print(f"  {C.R}nmap is not installed.{C.X}")
        problems.append("nmap is not installed, so nothing was scanned (menu [m] -> Install / check tools).")
        return nmap_xml, [], [], problems
    print(f"  {C.B}nmap 1/2{C.X}  {C.DIM}full-range sweep, all 65535 ports (-Pn -p- {timing}){C.X}")
    # -v makes nmap print each open port as soon as it finds it, so a sweep
    # that gets cut off can still report what it reached
    st, msg = _run_tool(["nmap", *fam, "-v", "-Pn", "-p-", timing, "-oX", stage1_xml, host], stage1_txt)
    print(f"    {msg}")
    ports = _open_ports(stage1_xml)
    if st != "ok":
        ports = sorted(set(ports) | set(_discovered_ports(stage1_txt)), key=int)
        hint = " Try nmap_timing -T3, a steadier VPN, or a longer SCAN_TIMEOUT." if st == "timeout" else ""
        problems.append(f"port sweep did not finish ({st}); the port list only covers what it reached.{hint}")
    if not ports:
        return nmap_xml, [], [], problems
    plist = ",".join(ports)
    print(f"    {C.G}{len(ports)} open:{C.X} {C.W}{plist}{C.X}")
    print(f"  {C.B}nmap 2/2{C.X}  {C.DIM}service + default scripts on open ports (-sV -sC){C.X}")
    st, msg = _run_tool(["nmap", *fam, "-sV", "-sC", "-Pn", "-p", plist, timing, "-oX", nmap_xml, host],
                        os.path.join(scan_dir, "nmap.txt"))
    print(f"    {msg}")
    rows = _parse_nmap_xml(nmap_xml)
    if st != "ok":
        problems.append(f"service scan (-sV -sC) did not finish ({st}); service names are guessed "
                        "from the port number and there are no script findings.")
        rows = _guess_rows(ports)
    elif not rows:
        problems.append("the sweep found open ports but the service scan saw none open; "
                        "listing them with names guessed from the port number.")
        rows = _guess_rows(ports)
    return nmap_xml, ports, rows, problems

def _web_urls(t, rows):
    """(label, url) for every web service to enumerate. A URL target is used as
    given. For a host target, one URL per http(s) port nmap found, with that
    port and the right scheme (not just http:// on port 80)."""
    if t["kind"] == "web":
        if "://" in t["display"]:
            return [("", t["display"])]
        return [("", _web_url("http", t["host"], t.get("port"), t.get("path")))]
    out = []
    for r in rows:
        svc = (r.get("service") or "").lower()
        if r.get("proto", "tcp") == "tcp" and "http" in svc:
            out.append((r["port"], _web_url(_http_scheme(svc, r["port"]), t["host"], r["port"])))
    return out

def _smb_present(rows):
    return any((r.get("service") or "").lower() in ("microsoft-ds", "netbios-ssn")
               or r.get("port") in ("445", "139") for r in rows)

def _as_root(cmd):
    """Prefix sudo when we are not root and the scan type needs it (nmap -sU).
    sudo asks for the password on the terminal even with output redirected."""
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        return ["sudo"] + cmd
    return cmd

def _extra_jobs(t, scan_dir, nmap_xml, rows, deep=False, udp=False):
    """Non-nmap recon jobs as (label, command, outpath), written in scan_dir.
    searchsploit whenever the service scan finished; UDP, SMB enum (netexec)
    and the web enum tools are opt-in via deep/udp. Uses CONFIG for the dir
    tool, timing and vhost domain."""
    host = t["host"]
    fam = _nmap_family(host)
    timing = CONFIG.get("nmap_timing") or "-T4"

    def p(name):
        return os.path.join(scan_dir, name)

    jobs = []
    if _parse_nmap_xml(nmap_xml):          # searchsploit needs real -sV output
        jobs.append(("searchsploit", ["searchsploit", "--nmap", nmap_xml], p("searchsploit.txt")))

    if udp:
        jobs.append(("nmap-udp",
                     _as_root(["nmap", *fam, "-sU", "-Pn", "--top-ports", str(CONFIG.get("udp_top_ports", "20")),
                               timing, "-oX", p("nmap_udp.xml"), host]),
                     p("nmap_udp.txt")))

    if deep:
        # extra nmap pass with the known-CVE vuln scripts, on the open ports
        tcp = [r["port"] for r in rows if r.get("proto", "tcp") == "tcp"]
        if tcp:
            jobs.append(("nmap-vuln",
                         ["nmap", *fam, "-sV", "--script", "vuln", "-Pn", "-p", ",".join(tcp), timing, host],
                         p("nmap_vuln.txt")))
        # SMB box -> netexec enumerates shares/users/null-session (read-only)
        if _smb_present(rows):
            jobs.append(("netexec-smb", ["netexec", "smb", host], p("netexec_smb.txt")))
        # each web service -> fingerprint + dir brute + quick issues + optional vhosts
        vhost = CONFIG.get("vhost_domain", "").strip()
        for port, url in _web_urls(t, rows):
            sfx = f"_{port}" if port else ""
            jobs.append((f"whatweb {url}", ["whatweb", "-a", "3", url], p(f"whatweb{sfx}.txt")))
            jobs.append((f"nikto {url}", ["nikto", "-h", url, "-maxtime", "120s", "-ask", "no"], p(f"nikto{sfx}.txt")))
            dc = _dir_cmd(url)
            if dc:
                jobs.append((f"{dc[0]} {url}", dc[1], p(f"dirscan{sfx}.txt")))
            if vhost and WORDLIST and shutil.which("ffuf"):
                jobs.append((f"ffuf-vhost {url}",
                             ["ffuf", "-u", url, "-H", f"Host: FUZZ.{vhost}",
                              "-w", WORDLIST, "-ac", "-s"],
                             p(f"vhosts{sfx}.txt")))
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
    parts = []
    try:
        names = sorted(os.listdir(scan_dir))
    except OSError:
        return
    for fn in names:
        fp = os.path.join(scan_dir, fn)
        if not os.path.isfile(fp) or fn in keep_as_is:
            continue
        if fn.endswith(".xml"):                    # intermediate nmap_ports/nmap_udp XML
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
    terminal and writes summary.md. No prompts. Returns the scan folder path,
    or None if the target was refused."""
    if not _valid_host(t.get("host") or ""):
        print(f"  {C.R}refusing to scan {t.get('display')!r}: the host is not a plain IP or hostname.{C.X}")
        return None
    base = _safe(t["display"]); tsd = _ts()
    scan_dir = os.path.join(RESULTS_DIR, f"{base}_{tsd}")
    os.makedirs(scan_dir, exist_ok=True)
    t.setdefault("results", [])

    def keep(fp):
        if os.path.exists(fp) and fp not in t["results"]:
            t["results"].append(fp)

    nmap_xml, ports, rows, problems = _run_nmap(t, scan_dir)
    if ports or udp:
        for label, cmd, outpath in _extra_jobs(t, scan_dir, nmap_xml, rows, deep=deep, udp=udp):
            print(f"  {C.B}running {label}...{C.X}")
            if cmd[0] == "sudo":
                print(f"    {C.DIM}this scan needs root; sudo may ask for your password{C.X}")
            st, msg = _run_tool(cmd, outpath)
            print(f"    {msg}")
            if label.startswith("nmap") and st not in ("ok", "skipped"):
                problems.append(f"{label} did not finish ({st}): {_last_line(outpath) or 'see details.txt'}")
    udp_rows = _parse_nmap_xml(os.path.join(scan_dir, "nmap_udp.xml")) if udp else []
    _scan_summary(t, rows, nmap_xml, scan_dir, udp_rows=udp_rows, problems=problems)
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
    if not scan_dir:
        pause(); return
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
    if not scan_dir:
        pause(); return
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
            print(f"  {C.DIM}no clipboard tool (install xclip or wl-clipboard). cmd:{C.X} {steps[int(ch)][1]}")
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
                if raw:
                    print(f"  {C.R}not a valid IP, host:port, or http(s):// URL.{C.X}")
                    pause()
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
        print(f"\n  {C.G}Wrote setup script to:{C.X} {path}")
        print(f"  Run it on any machine:  {C.CY}bash setup.sh{C.X}")
        print(f"  {C.DIM}Installs standard free tooling via apt, pacman or brew. Review it before running.{C.X}")
    except Exception as e:
        print(f"\n  {C.R}could not write setup.sh: {e}{C.X}")
    pause()

# whichever clipboard tool this box has (pbcopy on macOS, wl-copy on Wayland, X11 tools)
_CLIP_BIN = next((b for b in ("pbcopy", "wl-copy", "xclip", "xsel") if shutil.which(b)), "xclip")

# the binaries Poly actually invokes, in the order they matter
TOOL_AUDIT = [
    ("nmap", "nmap"), ("searchsploit", "searchsploit"),
    ("feroxbuster", "feroxbuster"), ("ffuf", "ffuf"), ("gobuster", "gobuster"),
    ("whatweb", "whatweb"), ("nikto", "nikto"),
    ("netexec", "netexec"), ("enum4linux-ng", "enum4linux-ng"),
    ("sqlmap", "sqlmap"), ("snmpwalk", "snmpwalk"),
    ("hydra", "hydra"), ("john", "john"), ("clipboard (copy)", _CLIP_BIN),
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
    print(f"  {C.DIM}Poly will write setup.sh next to itself and run it (apt/pacman/brew + pipx).")
    print(f"  apt and pacman will ask for your sudo password. To read it first: menu [m] -> Write setup.sh.{C.X}")
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
    for tool in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-ib"]):
        if shutil.which(tool[0]):
            try:
                if subprocess.run(tool, input=text.encode(), timeout=5).returncode == 0:
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
                print(f"  {C.DIM}no clipboard tool (install xclip or wl-clipboard). path:{C.X} {found[int(ch)]}")
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
    if not scan_dir:
        pause(); return
    _save(TARGETS_FILE, _targets_with(t))
    print(f"\n  {C.G}Done. Results under:{C.X} {C.CY}{scan_dir}{C.X}")
    print(f"  {C.DIM}Saved to the board - open [1] for a deep scan ([e]), loot, or status.{C.X}")
    _post_scan_actions(t)
    _save(TARGETS_FILE, _targets_with(t))
    pause()

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx"/>
<script id="ssl-cert" output="Subject: commonName=box.htb&#xa;Subject Alternative Name: DNS:dev.box.htb"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/><service name="abyss"/></port>
<port protocol="tcp" portid="5000"><state state="open"/><service name="unknown" servicefp="SF-Port5000-TCP:V=7.94%r(GetRequest,B7,&quot;HTTP/1\\.0\\x20200\\x20OK\\r\\nServer:\\x20Werkzeug&quot;)"/></port>
<port protocol="tcp" portid="6000"><state state="open"/><service name="unknown" servicefp="SF-Port6000-TCP:V=7.94%r(NULL,10,&quot;SSH-2\\.0-x&quot;)"/></port>
</ports></host></nmaprun>
"""

def _selftest():
    """Offline checks of the parsing and command building. No network, no tools."""
    ct = classify_target
    # option injection: nothing that starts with '-' may become a host
    for bad in ("--script=/tmp/x.nse", "-iL/etc/passwd", "-oN /tmp/x", "http://-x/",
                "ftp://box.htb", "box.htb:abc", "a b", "10.10.10.5:70000", "[::1", ""):
        assert ct(bad) is None, bad
    assert not _valid_host("-sV") and _valid_host("box.htb") and _valid_host("10.10.10.5")
    t = ct("10.10.10.5:8080")
    assert (t["kind"], t["host"], t["port"]) == ("host", "10.10.10.5", 8080), t
    t = ct("box.htb/admin")
    assert (t["kind"], t["host"], t["path"]) == ("web", "box.htb", "/admin"), t
    t = ct("https://box.htb:8443/app")
    assert (t["host"], t["port"], t["scheme"]) == ("box.htb", 8443, "https"), t
    t = ct("[dead:beef::1]:80")
    assert (t["host"], t["port"]) == ("dead:beef::1", 80), t
    assert ct("::1")["host"] == "::1"
    assert _nmap_family("dead:beef::1") == ["-6"] and _nmap_family("10.10.10.5") == []

    with tempfile.TemporaryDirectory() as d:
        xp = os.path.join(d, "nmap.xml")
        with open(xp, "w", encoding="utf-8") as f:
            f.write(_SAMPLE_XML)
        rows = _parse_nmap_xml(xp)
        assert [r["port"] for r in rows] == ["22", "443", "8080", "5000", "6000"], rows
        assert rows[1]["service"] == "ssl/http", rows[1]
        assert rows[3]["service"] == "http" and rows[4]["service"] == "unknown", rows[3:]
        assert _open_ports(xp) == ["22", "443", "8080", "5000", "6000"]
        rows = rows[:3]
        scripts = _parse_scripts(xp)
        assert _hostnames_from_scripts(scripts, "10.10.10.5") == ["box.htb", "dev.box.htb"]

        # web enum hits each http port with the right scheme
        host_t = ct("10.10.10.5")
        assert _web_urls(host_t, rows) == [("443", "https://10.10.10.5/"),
                                           ("8080", "http://10.10.10.5:8080/")], _web_urls(host_t, rows)
        assert _web_urls(ct("[dead:beef::1]"), rows)[1][1] == "http://[dead:beef::1]:8080/"
        assert _web_urls(ct("http://box.htb:81/x"), rows) == [("", "http://box.htb:81/x")]
        assert "https://10.10.10.5/" in _service_hint("ssl/http", "443", "10.10.10.5")

        # a sweep killed part way: XML has no ports, the -v log still does
        trunc = os.path.join(d, "trunc.xml")
        with open(trunc, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="22">')
        assert _open_ports(trunc) == [] and _parse_nmap_xml(trunc) == []
        log = os.path.join(d, "nmap_ports.txt")
        with open(log, "w", encoding="utf-8") as f:
            f.write("Discovered open port 8080/tcp on 10.10.10.5\n"
                    "Discovered open port 22/tcp on 10.10.10.5\n"
                    "Discovered open port 22/tcp on 10.10.10.5\n")
        assert _discovered_ports(log) == ["22", "8080"]
        assert _guess_rows(["22"])[0]["service"] == "ssh"

        # a tool that exits non-zero is reported as failed, not done
        if shutil.which("false"):
            st, _ = _run_tool(["false"], os.path.join(d, "f.txt"))
            assert st == "failed", st
        st, _ = _run_tool(["poly-no-such-tool"], os.path.join(d, "n.txt"))
        assert st == "skipped", st

def main():
    if "--check" in sys.argv:
        _selftest()
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
