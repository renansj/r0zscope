# r0zscope

**Automated web reconnaissance framework built in Go.**

I got tired of running the same 15 tools manually every time I started a pentest or a CTF box. Copy-pasting commands, piping outputs, deduplicating results - it was the same ritual over and over. So I built r0zscope to do it all in one shot: subdomain enumeration, HTTP probing, port scanning, crawling, JS analysis, vulnerability scanning, and more - all running in parallel with organized output.

It orchestrates 40+ recon tools into a single pipeline. Each tool writes to its own folder, results get merged and deduplicated automatically, and you get a clean report at the end. It also has a CTF mode for local targets configured in `/etc/hosts`, where it does vhost brute-force via Host header instead of internet-based subdomain enumeration.

**By R0Z (Renan Zapelini)**

---

## Install

### Via `go install` (recommended)

```bash
go install github.com/renansj/r0zscope@latest
```

### From source

```bash
git clone https://github.com/renansj/r0zscope.git
cd r0zscope
go build -ldflags "-s -w" -o r0zscope .
sudo mv r0zscope /usr/local/bin/
```

### From releases

Download pre-built binaries for Linux, macOS, and Windows from the [Releases](https://github.com/renansj/r0zscope/releases) page.

### Install recon tools

r0zscope orchestrates external tools. Install them all at once:

```bash
make install-all-tools
```

Or check what's missing and install interactively:

```bash
r0zscope -check
r0zscope -install
```

---

## Usage

### Full recon on a public target

```bash
r0zscope -target example.com
r0zscope -target example.com -threads 30 -verbose
r0zscope -target example.com -proxy http://127.0.0.1:8080
r0zscope -target example.com -wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Run specific phases

```bash
r0zscope -target example.com -only subdomains,httpprobe,vulnscan
r0zscope -target example.com -skip portscan,ssl,content
```

### CTF mode (local targets)

For HTB, THM, CTFs, or any target configured in `/etc/hosts`:

```bash
r0zscope -target test.htb -ctf
r0zscope -target test.htb -ctf -vhost-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

What changes in CTF mode:

| Phase | Normal mode | CTF mode (`-ctf`) |
|-------|------------|-------------------|
| Subdomains | subfinder, assetfinder, amass, crt.sh, etc. | **Vhost brute-force via Host header** (ffuf/gobuster) |
| DNS | dnsx, dnsrecon | **Skipped** (DNS is local) |
| URLs | waybackurls, gau, paramspider + crawlers | **Local crawlers only** (katana, gospider, hakrawler) |
| Takeover | subjack, subzy | **Skipped** |
| Everything else | Normal | Normal |

---

## Pipeline (11 phases)

| # | Phase | Tools |
|---|-------|-------|
| 1 | Subdomain enumeration | subfinder, assetfinder, amass, findomain, crt.sh, github-subdomains, puredns, shuffledns |
| 2 | DNS resolution | dnsx, dnsrecon |
| 3 | HTTP probing | httpx, httprobe |
| 3.5 | Fingerprinting | wafw00f, whatweb |
| 4 | Port scanning | naabu, nmap |
| 5 | URL discovery | waybackurls, gau, katana, gospider, hakrawler, paramspider, unfurl, gf, uro |
| 5.5 | Content discovery | ffuf, feroxbuster, gobuster, dirsearch, arjun |
| 6 | JS analysis (local files) | linkfinder, SecretFinder, trufflehog, semgrep, subjs |
| 7 | Subdomain takeover | subzy, subjack |
| 8 | Vulnerability scanning | nuclei, nikto, dalfox, sqlmap, crlfuzz, corsy, wpscan, commix |
| 9 | SSL/TLS analysis | sslyze, testssl.sh |

JS analysis runs on **locally downloaded files** - JS URLs discovered by katana/gospider/waybackurls are filtered, downloaded via wget in parallel, then linkfinder, SecretFinder, trufflehog, and semgrep analyze the local files. Each analysis tool runs in its own goroutine, and linkfinder/SecretFinder process individual files with parallel workers.

---

## Flags

```
Target:
  -target          Target domain (required)

Mode:
  -ctf             CTF local mode - vhost brute-force, no internet tools

Config:
  -config          YAML config file
  -output          Output directory (default: recon-output/<target>)
  -threads         Thread count (default: auto)
  -verbose         Verbose output
  -proxy           HTTP proxy (e.g. http://127.0.0.1:8080)
  -depth           Crawl depth (default: 3)
  -rate-limit      Global rate limit (req/s, 0 = unlimited)

Wordlists:
  -wordlist        Wordlist for subdomain brute-force
  -vhost-wordlist  Wordlist for vhost brute-force (CTF mode)

Nuclei:
  -severity        Nuclei severity filter (default: critical,high,medium)

Phases:
  -skip            Phases to skip (comma-separated)
  -only            Run only these phases (comma-separated)

Tools:
  -check           Check installed tools
  -install         Install missing tools
  -install-script  Generate install script
  -gen-config      Generate example YAML config
```

---

## Output structure

```
recon-output/example.com/
├── _merged/
│   ├── all-subdomains.txt
│   ├── all-alive.txt
│   ├── all-urls.txt
│   ├── urls-with-params.txt
│   └── js-files.txt
├── subfinder/
├── assetfinder/
├── katana/
│   └── urls.txt
├── _jsfiles/
│   └── downloaded/            ← JS files downloaded via wget
├── linkfinder/
│   └── endpoints.txt          ← extracted from local JS
├── secretfinder/
│   └── secrets.txt            ← extracted from local JS
├── trufflehog/
│   └── secrets.txt            ← filesystem scan on JS dir
├── semgrep/
│   ├── findings.txt           ← static analysis results
│   └── findings.json
├── nuclei/
│   ├── findings.txt
│   └── fuzz-findings.txt
├── gf/
│   ├── xss.txt
│   ├── sqli.txt
│   └── ...
├── vhost-brute/               ← CTF mode only
│   └── vhosts.txt
├── ...                        ← one folder per tool
└── REPORT.txt
```

---

## Release pipeline

Releases are automated via GitHub Actions + GoReleaser. To create a new release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers the pipeline that builds binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64), then publishes them as a GitHub Release.

Users can then install with:

```bash
go install github.com/renansj/r0zscope@latest
```

Or download binaries directly from the [Releases](https://github.com/renansj/r0zscope/releases) page.

---

## License

MIT
