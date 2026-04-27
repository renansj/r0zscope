package runner

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

// ToolInfo describes a required external tool.
type ToolInfo struct {
	Name        string
	Binary      string
	InstallCmd  string
	Description string
	Required    bool
	GoInstall   string
	Category    string
}

// AllTools returns the complete list of tools used.
func AllTools() []ToolInfo {
	return []ToolInfo{
		{
			Name:        "subfinder",
			Binary:      "subfinder",
			InstallCmd:  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			GoInstall:   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			Description: "Passive subdomain enumeration via multiple sources",
			Required:    true,
			Category:    "subdomain",
		},
		{
			Name:        "assetfinder",
			Binary:      "assetfinder",
			InstallCmd:  "go install -v github.com/tomnomnom/assetfinder@latest",
			GoInstall:   "github.com/tomnomnom/assetfinder@latest",
			Description: "Asset and subdomain discovery",
			Required:    true,
			Category:    "subdomain",
		},
		{
			Name:        "amass",
			Binary:      "amass",
			InstallCmd:  "go install -v github.com/owasp-amass/amass/v4/...@master",
			GoInstall:   "github.com/owasp-amass/amass/v4/...@master",
			Description: "Advanced subdomain enumeration with OSINT",
			Required:    false,
			Category:    "subdomain",
		},
		{
			Name:        "findomain",
			Binary:      "findomain",
			InstallCmd:  "apt install -y findomain",
			Description: "Fast subdomain enumeration (Rust)",
			Required:    false,
			Category:    "subdomain",
		},
		{
			Name:        "shuffledns",
			Binary:      "shuffledns",
			InstallCmd:  "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
			GoInstall:   "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
			Description: "Subdomain brute-force with massdns wrapper",
			Required:    false,
			Category:    "subdomain",
		},
		{
			Name:        "github-subdomains",
			Binary:      "github-subdomains",
			InstallCmd:  "go install -v github.com/gwen001/github-subdomains@latest",
			GoInstall:   "github.com/gwen001/github-subdomains@latest",
			Description: "Subdomains via GitHub scraping",
			Required:    false,
			Category:    "subdomain",
		},
		{
			Name:        "crt.sh query",
			Binary:      "curl",
			InstallCmd:  "apt install -y curl",
			Description: "Certificate Transparency logs via crt.sh (uses curl)",
			Required:    false,
			Category:    "subdomain",
		},
		{
			Name:        "dnsx",
			Binary:      "dnsx",
			InstallCmd:  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
			GoInstall:   "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
			Description: "Mass DNS resolution and brute-force",
			Required:    false,
			Category:    "dns",
		},
		{
			Name:        "puredns",
			Binary:      "puredns",
			InstallCmd:  "go install -v github.com/d3mondev/puredns/v2@latest",
			GoInstall:   "github.com/d3mondev/puredns/v2@latest",
			Description: "DNS resolution and brute-force with wildcard filtering",
			Required:    false,
			Category:    "dns",
		},
		{
			Name:        "massdns",
			Binary:      "massdns",
			InstallCmd:  "apt install -y massdns || git clone https://github.com/blechschmidt/massdns.git && cd massdns && make",
			Description: "Ultra-fast DNS resolution (backend for shuffledns/puredns)",
			Required:    false,
			Category:    "dns",
		},
		{
			Name:        "dnsrecon",
			Binary:      "dnsrecon",
			InstallCmd:  "apt install -y dnsrecon",
			Description: "Advanced DNS enumeration (zone transfer, brute, cache snoop)",
			Required:    false,
			Category:    "dns",
		},
		{
			Name:        "httpx",
			Binary:      "httpx",
			InstallCmd:  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
			GoInstall:   "github.com/projectdiscovery/httpx/cmd/httpx@latest",
			Description: "HTTP probe with tech detection and status codes",
			Required:    true,
			Category:    "probe",
		},
		{
			Name:        "httprobe",
			Binary:      "httprobe",
			InstallCmd:  "go install -v github.com/tomnomnom/httprobe@latest",
			GoInstall:   "github.com/tomnomnom/httprobe@latest",
			Description: "Fast HTTP/HTTPS alive host check",
			Required:    false,
			Category:    "probe",
		},
		{
			Name:        "naabu",
			Binary:      "naabu",
			InstallCmd:  "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
			GoInstall:   "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
			Description: "Fast port scanner (SYN/CONNECT)",
			Required:    false,
			Category:    "portscan",
		},
		{
			Name:        "nmap",
			Binary:      "nmap",
			InstallCmd:  "apt install -y nmap",
			Description: "Full network scanner (service detection, NSE scripts)",
			Required:    false,
			Category:    "portscan",
		},
		{
			Name:        "wafw00f",
			Binary:      "wafw00f",
			InstallCmd:  "pip3 install wafw00f",
			Description: "WAF detection and fingerprinting",
			Required:    false,
			Category:    "waf",
		},
		{
			Name:        "whatweb",
			Binary:      "whatweb",
			InstallCmd:  "apt install -y whatweb",
			Description: "Web fingerprinting (CMS, frameworks, servers)",
			Required:    false,
			Category:    "fingerprint",
		},
		{
			Name:        "katana",
			Binary:      "katana",
			InstallCmd:  "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
			GoInstall:   "github.com/projectdiscovery/katana/cmd/katana@latest",
			Description: "Next-gen web crawler",
			Required:    true,
			Category:    "crawl",
		},
		{
			Name:        "gospider",
			Binary:      "gospider",
			InstallCmd:  "go install -v github.com/jaeles-project/gospider@latest",
			GoInstall:   "github.com/jaeles-project/gospider@latest",
			Description: "Fast web spider in Go",
			Required:    false,
			Category:    "crawl",
		},
		{
			Name:        "hakrawler",
			Binary:      "hakrawler",
			InstallCmd:  "go install -v github.com/hakluke/hakrawler@latest",
			GoInstall:   "github.com/hakluke/hakrawler@latest",
			Description: "Fast crawler for endpoint discovery",
			Required:    false,
			Category:    "crawl",
		},
		{
			Name:        "waybackurls",
			Binary:      "waybackurls",
			InstallCmd:  "go install -v github.com/tomnomnom/waybackurls@latest",
			GoInstall:   "github.com/tomnomnom/waybackurls@latest",
			Description: "URL extraction from Wayback Machine",
			Required:    true,
			Category:    "url",
		},
		{
			Name:        "gau",
			Binary:      "gau",
			InstallCmd:  "go install -v github.com/lc/gau/v2/cmd/gau@latest",
			GoInstall:   "github.com/lc/gau/v2/cmd/gau@latest",
			Description: "URLs from AlienVault OTX, Wayback Machine and Common Crawl",
			Required:    false,
			Category:    "url",
		},
		{
			Name:        "anew",
			Binary:      "anew",
			InstallCmd:  "go install -v github.com/tomnomnom/anew@latest",
			GoInstall:   "github.com/tomnomnom/anew@latest",
			Description: "Incremental line deduplication",
			Required:    true,
			Category:    "url",
		},
		{
			Name:        "unfurl",
			Binary:      "unfurl",
			InstallCmd:  "go install -v github.com/tomnomnom/unfurl@latest",
			GoInstall:   "github.com/tomnomnom/unfurl@latest",
			Description: "URL component extraction (paths, params, keys)",
			Required:    false,
			Category:    "url",
		},
		{
			Name:        "qsreplace",
			Binary:      "qsreplace",
			InstallCmd:  "go install -v github.com/tomnomnom/qsreplace@latest",
			GoInstall:   "github.com/tomnomnom/qsreplace@latest",
			Description: "Query string value replacement for fuzzing",
			Required:    false,
			Category:    "url",
		},
		{
			Name:        "uro",
			Binary:      "uro",
			InstallCmd:  "pip3 install uro",
			Description: "Smart URL deduplication (removes similar)",
			Required:    false,
			Category:    "url",
		},
		{
			Name:        "arjun",
			Binary:      "arjun",
			InstallCmd:  "pip3 install arjun",
			Description: "Hidden HTTP parameter discovery",
			Required:    false,
			Category:    "param",
		},
		{
			Name:        "paramspider",
			Binary:      "paramspider",
			InstallCmd:  "pip3 install paramspider",
			Description: "Parameter mining from historical URLs",
			Required:    false,
			Category:    "param",
		},
		{
			Name:        "ffuf",
			Binary:      "ffuf",
			InstallCmd:  "go install -v github.com/ffuf/ffuf/v2@latest",
			GoInstall:   "github.com/ffuf/ffuf/v2@latest",
			Description: "Fast web fuzzer (directory brute, vhost, params)",
			Required:    false,
			Category:    "fuzz",
		},
		{
			Name:        "feroxbuster",
			Binary:      "feroxbuster",
			InstallCmd:  "apt install -y feroxbuster || cargo install feroxbuster",
			Description: "Recursive directory brute-force (Rust, fast)",
			Required:    false,
			Category:    "fuzz",
		},
		{
			Name:        "dirsearch",
			Binary:      "dirsearch",
			InstallCmd:  "pip3 install dirsearch",
			Description: "Directory brute-force with smart wordlists",
			Required:    false,
			Category:    "fuzz",
		},
		{
			Name:        "gobuster",
			Binary:      "gobuster",
			InstallCmd:  "go install -v github.com/OJ/gobuster/v3@latest",
			GoInstall:   "github.com/OJ/gobuster/v3@latest",
			Description: "Directory/DNS/vhost brute-force in Go",
			Required:    false,
			Category:    "fuzz",
		},
		{
			Name:        "linkfinder",
			Binary:      "linkfinder",
			InstallCmd:  "git clone https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder && sudo ln -sf /opt/LinkFinder/linkfinder.py /usr/local/bin/linkfinder",
			Description: "Endpoint extraction from JavaScript files",
			Required:    false,
			Category:    "js",
		},
		{
			Name:        "secretfinder",
			Binary:      "SecretFinder",
			InstallCmd:  "git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder && sudo ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/SecretFinder",
			Description: "Secret/API key extraction from JavaScript",
			Required:    false,
			Category:    "js",
		},
		{
			Name:        "getJS",
			Binary:      "getJS",
			InstallCmd:  "go install -v github.com/003random/getJS@latest",
			GoInstall:   "github.com/003random/getJS@latest",
			Description: "JS file URL extraction from web pages",
			Required:    false,
			Category:    "js",
		},
		{
			Name:        "subjs",
			Binary:      "subjs",
			InstallCmd:  "go install -v github.com/lc/subjs@latest",
			GoInstall:   "github.com/lc/subjs@latest",
			Description: "JS file extraction from URL list",
			Required:    false,
			Category:    "js",
		},
		{
			Name:        "trufflehog",
			Binary:      "trufflehog",
			InstallCmd:  "pip3 install trufflehog",
			Description: "Secret and credential detection in files (filesystem scan)",
			Required:    false,
			Category:    "js",
		},
		{
			Name:        "subjack",
			Binary:      "subjack",
			InstallCmd:  "go install -v github.com/haccer/subjack@latest",
			GoInstall:   "github.com/haccer/subjack@latest",
			Description: "Subdomain takeover detection",
			Required:    false,
			Category:    "takeover",
		},
		{
			Name:        "subzy",
			Binary:      "subzy",
			InstallCmd:  "go install -v github.com/PentestPad/subzy@latest",
			GoInstall:   "github.com/PentestPad/subzy@latest",
			Description: "Subdomain takeover detection (more up-to-date)",
			Required:    false,
			Category:    "takeover",
		},
		{
			Name:        "nuclei",
			Binary:      "nuclei",
			InstallCmd:  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			GoInstall:   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			Description: "Template-based vulnerability scanner",
			Required:    true,
			Category:    "vuln",
		},
		{
			Name:        "nikto",
			Binary:      "nikto",
			InstallCmd:  "apt install -y nikto",
			Description: "Classic web vulnerability scanner",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "wpscan",
			Binary:      "wpscan",
			InstallCmd:  "apt install -y wpscan || gem install wpscan",
			Description: "WordPress vulnerability scanner",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "dalfox",
			Binary:      "dalfox",
			InstallCmd:  "go install -v github.com/hahwul/dalfox/v2@latest",
			GoInstall:   "github.com/hahwul/dalfox/v2@latest",
			Description: "Advanced XSS scanner with parameter analysis",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "sqlmap",
			Binary:      "sqlmap",
			InstallCmd:  "apt install -y sqlmap",
			Description: "Automatic SQL injection detection and exploitation",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "commix",
			Binary:      "commix",
			InstallCmd:  "apt install -y commix",
			Description: "Command injection detection and exploitation",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "crlfuzz",
			Binary:      "crlfuzz",
			InstallCmd:  "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
			GoInstall:   "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
			Description: "CRLF injection scanner",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "corsy",
			Binary:      "corsy",
			InstallCmd:  "git clone https://github.com/s0md3v/Corsy.git /opt/Corsy && sudo ln -sf /opt/Corsy/corsy.py /usr/local/bin/corsy",
			Description: "CORS misconfiguration scanner",
			Required:    false,
			Category:    "vuln",
		},
		{
			Name:        "testssl",
			Binary:      "testssl.sh",
			InstallCmd:  "apt install -y testssl.sh",
			Description: "Full TLS/SSL analysis (ciphers, protocols, vulns)",
			Required:    false,
			Category:    "ssl",
		},
		{
			Name:        "sslyze",
			Binary:      "sslyze",
			InstallCmd:  "pip3 install sslyze",
			Description: "SSL/TLS configuration analysis",
			Required:    false,
			Category:    "ssl",
		},
		{
			Name:        "gf",
			Binary:      "gf",
			InstallCmd:  "go install -v github.com/tomnomnom/gf@latest",
			GoInstall:   "github.com/tomnomnom/gf@latest",
			Description: "Grep patterns for interesting URLs (XSS, SQLi, SSRF, etc.)",
			Required:    false,
			Category:    "url",
		},
	}
}

// CheckResult stores the verification result for a tool.
type CheckResult struct {
	Tool      ToolInfo
	Available bool
	Path      string
	Version   string
}

// CheckTools verifies which tools are installed.
func CheckTools() []CheckResult {
	tools := AllTools()
	results := make([]CheckResult, len(tools))

	for i, tool := range tools {
		path, err := exec.LookPath(tool.Binary)
		results[i] = CheckResult{
			Tool:      tool,
			Available: err == nil,
			Path:      path,
		}

		if err == nil {
			out, verr := exec.Command(tool.Binary, "-version").CombinedOutput()
			if verr == nil {
				version := strings.TrimSpace(string(out))
				if len(version) > 80 {
					version = version[:80]
				}
				results[i].Version = version
			}
		}
	}

	return results
}

// GetMissingRequired returns required tools that are not installed.
func GetMissingRequired(results []CheckResult) []CheckResult {
	var missing []CheckResult
	for _, r := range results {
		if r.Tool.Required && !r.Available {
			missing = append(missing, r)
		}
	}
	return missing
}

// GetMissingOptional returns optional tools that are not installed.
func GetMissingOptional(results []CheckResult) []CheckResult {
	var missing []CheckResult
	for _, r := range results {
		if !r.Tool.Required && !r.Available {
			missing = append(missing, r)
		}
	}
	return missing
}

// PrintToolStatus prints the status of all tools grouped by category.
func PrintToolStatus(results []CheckResult) {
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	bold := color.New(color.Bold)

	fmt.Println()
	cyan.Println("╔══════════════════════════════════════════════════════════════╗")
	cyan.Println("║                      TOOL CHECK                            ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════╝")

	categories := []struct {
		key  string
		name string
	}{
		{"subdomain", "Subdomain Enumeration"},
		{"dns", "DNS"},
		{"probe", "HTTP Probing"},
		{"portscan", "Port Scanning"},
		{"waf", "WAF Detection"},
		{"fingerprint", "Fingerprinting"},
		{"crawl", "Crawling"},
		{"url", "URL Discovery & Processing"},
		{"param", "Parameter Discovery"},
		{"fuzz", "Directory/Content Discovery"},
		{"js", "JavaScript Analysis"},
		{"takeover", "Subdomain Takeover"},
		{"vuln", "Vulnerability Scanning"},
		{"ssl", "SSL/TLS Analysis"},
	}

	available := 0
	total := 0
	for _, r := range results {
		total++
		if r.Available {
			available++
		}
	}

	fmt.Println()
	bold.Printf("  %d/%d tools available\n", available, total)

	for _, cat := range categories {
		hasTools := false
		for _, r := range results {
			if r.Tool.Category == cat.key {
				hasTools = true
				break
			}
		}
		if !hasTools {
			continue
		}

		fmt.Println()
		bold.Printf("  ── %s ──\n", cat.name)

		for _, r := range results {
			if r.Tool.Category != cat.key {
				continue
			}

			reqTag := ""
			if r.Tool.Required {
				reqTag = yellow.Sprint(" [REQUIRED]")
			}

			if r.Available {
				green.Printf("    ✓ %-20s", r.Tool.Name)
			} else {
				red.Printf("    ✗ %-20s", r.Tool.Name)
			}
			fmt.Printf(" %s%s\n", r.Tool.Description, reqTag)
		}
	}
	fmt.Println()
}

// GenerateInstallScript generates a bash script to install missing tools.
func GenerateInstallScript(missing []CheckResult) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Recon tool installation script\n")
	sb.WriteString("# Auto-generated by r0zscope\n\n")
	sb.WriteString("set -e\n\n")

	sb.WriteString("echo '[*] Checking Go...'\n")
	sb.WriteString("if ! command -v go &> /dev/null; then\n")
	sb.WriteString("    echo '[-] Go not found. Install Go first: https://go.dev/dl/'\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("fi\n\n")

	for _, r := range missing {
		sb.WriteString(fmt.Sprintf("echo '[*] Installing %s - %s'\n", r.Tool.Name, r.Tool.Description))
		sb.WriteString(fmt.Sprintf("%s\n", r.Tool.InstallCmd))
		sb.WriteString(fmt.Sprintf("echo '[+] %s installed.'\n\n", r.Tool.Name))
	}

	sb.WriteString("echo '[+] All tools installed successfully.'\n")
	return sb.String()
}
