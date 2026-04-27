BINARY=r0zscope
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR=build
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux clean install check deps

all: build

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 .

build-arm:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64 .

install: build
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	chmod +x /usr/local/bin/$(BINARY)

clean:
	rm -rf $(BUILD_DIR) dist/

check:
	go vet ./...
	go build ./...

deps:
	go mod tidy
	go mod download

install-go-tools:
	@echo "[*] Installing Go tools..."
	-go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	-go install -v github.com/tomnomnom/assetfinder@latest
	-go install -v github.com/owasp-amass/amass/v4/...@master
	-go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
	-go install -v github.com/tomnomnom/httprobe@latest
	-go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	-go install -v github.com/projectdiscovery/katana/cmd/katana@latest
	-go install -v github.com/tomnomnom/waybackurls@latest
	-go install -v github.com/lc/gau/v2/cmd/gau@latest
	-go install -v github.com/tomnomnom/anew@latest
	-go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	-go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	-go install -v github.com/jaeles-project/gospider@latest
	-go install -v github.com/tomnomnom/unfurl@latest
	-go install -v github.com/tomnomnom/qsreplace@latest
	-go install -v github.com/tomnomnom/gf@latest
	-go install -v github.com/haccer/subjack@latest
	-go install -v github.com/PentestPad/subzy@latest
	-go install -v github.com/hahwul/dalfox/v2@latest
	-go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
	-go install -v github.com/ffuf/ffuf/v2@latest
	-go install -v github.com/OJ/gobuster/v3@latest
	-go install -v github.com/hakluke/hakrawler@latest
	-go install -v github.com/lc/subjs@latest
	-go install -v github.com/003random/getJS@latest
	-go install -v github.com/gwen001/github-subdomains@latest
	-go install -v github.com/d3mondev/puredns/v2@latest
	-go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
	@echo "[+] Go tools installed."

install-pip-tools:
	@echo "[*] Installing Python tools..."
	-pipx install wafw00f
	-pipx install arjun
	-pipx install paramspider
	-pipx install uro
	-pipx install sslyze
	-pipx install dirsearch
	-pipx install trufflehog
	@echo "[+] Python tools installed."

install-apt-tools:
	@echo "[*] Installing apt tools..."
	sudo apt install -y nmap nikto whatweb wpscan sqlmap commix massdns dnsrecon feroxbuster seclists
	@echo "[+] Apt tools installed."

install-all-tools: install-go-tools install-pip-tools install-apt-tools
	@echo "[*] Updating nuclei templates..."
	nuclei -update-templates
	@echo "[*] Installing gf patterns..."
	mkdir -p ~/.gf
	git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true
	cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null || true
	@echo "[+] All done. Run: r0zscope -check"
