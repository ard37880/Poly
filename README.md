# Poly

```
    ██████╗  ██████╗ ██╗  ██╗   ██╗████████╗ ██████╗  ██████╗ ██╗
    ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║
    ██████╔╝██║   ██║██║   ╚████╔╝    ██║   ██║   ██║██║   ██║██║
    ██╔═══╝ ██║   ██║██║    ╚██╔╝     ██║   ██║   ██║██║   ██║██║
    ██║     ╚██████╔╝███████╗██║      ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝      ╚═════╝ ╚══════╝╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

**A single-file recon and enumeration console.** Paste an IP or a URL, press enter, and Poly runs a sensible scan pipeline, parses the results, and tells you what to look at next. Pure Python standard library, no dependencies, one file.

[![Python 3](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)](#)

```bash
python3 poly.py
```

> [!WARNING]
> **Authorized targets only.** Poly runs live scans against whatever you point it at. Only use it against systems you own or have **explicit, written authorization** to test. Scanning anything else is likely illegal. Poly asks you to confirm authorization before every scan for this reason.

---

## What it does

Poly is an **orchestrator**. It drives the standard, freely-available tools you already know (nmap, searchsploit, feroxbuster/ffuf/gobuster, whatweb, nikto, netexec, enum4linux-ng, and friends), reads their output, and surfaces the findings in one place. It contains **no exploit code, payloads, or auto-exploitation** — it tells you where to look and hands you the methodology; you do the actual attacking by hand with the right tool.

- **Paste-and-scan.** Paste an IP (v4 or v6), `host:port`, or an `http(s)://` URL at the menu and it classifies the target, scans it, and saves it to the board. Anything that isn't a plain IP or hostname is refused, so a target can never be passed to nmap as an option.
- **Two-stage nmap.** A fast full-range sweep (`-Pn -p-`) finds the open ports, then `-sV -sC` runs against **only those ports** — faster than one `-sV -sC -p-` and just as thorough. `-Pn` so ping-blocking hosts aren't skipped as "down", and no forced packet rate so a lossy VPN doesn't drop ports silently.
- **CVE lookup.** `searchsploit --nmap` maps detected service versions to known public exploits, with the top matches surfaced.
- **Script findings.** Parses the nmap NSE output and pulls out the real leads — titles, TLS cert names, anonymous FTP, SMB shares/signing, `robots.txt`, git exposure, discovered hostnames (as a ready `/etc/hosts` line).
- **Deep scan (opt-in).** Adds a top-ports UDP sweep, nmap `vuln` scripts, SMB enumeration (netexec), and web enum (whatweb, nikto, directory brute, optional vhost fuzzing) on every web port nmap found, with the right port and http/https. UDP scanning needs root, so if you aren't root Poly runs that one nmap through `sudo` and it may ask for your password.
- **Honest about failures.** If an nmap stage times out or errors, the summary says so under **Scan problems** and keeps whatever ports it did find, instead of reporting "no open ports".
- **Arsenal.** Finds where your wordlists (rockyou, SecLists, raft lists, usernames, subdomains) and payload repos (PayloadsAllTheThings, SecLists) actually live on the box and copies a path to your clipboard. It indexes what's installed; it never ships lists or runs anything.
- **Offline cheat sheet.** A full recon/enumeration command reference ([`CHEATSHEET.md`](CHEATSHEET.md)) viewable from inside the tool.
- **setup.sh generator.** Writes an `apt`/`pacman` installer for the standard tooling, to review before running.

## Quick start

```bash
git clone https://github.com/steckh/Poly
cd Poly
python3 poly.py
```

At the menu, paste a target and press enter, or:

| Key | Does |
|-----|------|
| `1` | Targets board — add, scan (`r` recon / `e` deep), review |
| `s` | Scan every target on the board |
| `w` | Arsenal — locate wordlists + payload refs |
| `t` | "What tool do I use?" for a given finding |
| `k` | Search your saved scan results for a keyword |
| `c` | The offline cheat sheet |
| `m` | More — install/check tools, write `setup.sh`, quick links, export a report |

## Scan output

Each scan gets its own tidy folder, `results/<target>_<timestamp>/`, with **three files**:

| File | What it is |
|------|------------|
| `summary.md` | the readable summary: open ports, script findings, next steps, top CVE matches |
| `nmap.xml` | the raw stage-2 scan, kept for re-parsing |
| `details.txt` | every other raw tool output folded into one, under `===== name =====` headers |

Prefer every raw per-tool file instead? Set `CONFIG["keep_raw_files"] = True`.

## Configure

Tooling knobs live in the `CONFIG` dict at the top of `poly.py`:

```python
CONFIG = {
    "dir_tool": "feroxbuster",   # feroxbuster | ffuf | gobuster | dirb
    "dir_wordlist": "",          # "" = auto-detect; or an absolute path
    "nmap_timing": "-T4",        # -T4 fast, -T3 reliable on a lossy link
    "udp_top_ports": "20",       # top UDP ports the deep scan sweeps
    "vhost_domain": "",          # e.g. "htb" -> deep scan fuzzes vhosts
    "keep_raw_files": False,     # False = tidy 3-file folder; True = every raw file
}
```

## Files it writes

- `poly_targets.json` — the target board
- `results/` — per-scan folders
- `setup.sh` — generated on demand

All created next to the script and listed in `.gitignore`, so your working state isn't committed.

## Requirements

Python 3.8+ and whichever CLI tools you want Poly to drive (nmap at minimum). Menu `m → Install / check tools` audits what's present and can install the rest with apt, pacman, or Homebrew. Packages go in one at a time and anything your distro doesn't carry is listed at the end (a few, like enum4linux-ng, are only packaged on Kali/Parrot). Python CTF libs go in their own venv at `~/.venvs/ctf`. Runs on Linux, macOS, and WSL.

`python3 poly.py --check` runs an offline self-test of the target parsing and nmap handling.

## License

MIT. See [LICENSE](LICENSE).
