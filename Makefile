BINARY=r0zscope
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR=build
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux clean install check deps

define go_install
	@if command -v $(1) >/dev/null 2>&1; then \
		echo "  [ok] $(1) already installed"; \
	else \
		echo "  [*] Installing $(1)..."; \
		go install -v $(2) || echo "  [!] Failed to install $(1)"; \
	fi
endef

define pipx_install
	@if command -v $(1) >/dev/null 2>&1; then \
		echo "  [ok] $(1) already installed"; \
	else \
		echo "  [*] Installing $(1)..."; \
		pipx install $(2) || echo "  [!] Failed to install $(1)"; \
	fi
endef

define apt_install
	@if command -v $(1) >/dev/null 2>&1; then \
		echo "  [ok] $(1) already installed"; \
	else \
		echo "  [*] Installing $(1)..."; \
		sudo apt install -y $(2) || echo "  [!] Failed to install $(1)"; \
	fi
endef

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
	@echo "[*] Checking Go tools..."
	$(call go_install,subfinder,github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
	$(call go_install,assetfinder,github.com/tomnomnom/assetfinder@latest)
	$(call go_install,amass,github.com/owasp-amass/amass/v4/...@master)
	$(call go_install,httpx,github.com/projectdiscovery/httpx/cmd/httpx@latest)
	$(call go_install,httprobe,github.com/tomnomnom/httprobe@latest)
	$(call go_install,nuclei,github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
	$(call go_install,katana,github.com/projectdiscovery/katana/cmd/katana@latest)
	$(call go_install,waybackurls,github.com/tomnomnom/waybackurls@latest)
	$(call go_install,gau,github.com/lc/gau/v2/cmd/gau@latest)
	$(call go_install,anew,github.com/tomnomnom/anew@latest)
	$(call go_install,dnsx,github.com/projectdiscovery/dnsx/cmd/dnsx@latest)
	$(call go_install,naabu,github.com/projectdiscovery/naabu/v2/cmd/naabu@latest)
	$(call go_install,gospider,github.com/jaeles-project/gospider@latest)
	$(call go_install,unfurl,github.com/tomnomnom/unfurl@latest)
	$(call go_install,qsreplace,github.com/tomnomnom/qsreplace@latest)
	$(call go_install,gf,github.com/tomnomnom/gf@latest)
	$(call go_install,subjack,github.com/haccer/subjack@latest)
	$(call go_install,subzy,github.com/PentestPad/subzy@latest)
	$(call go_install,dalfox,github.com/hahwul/dalfox/v2@latest)
	$(call go_install,crlfuzz,github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest)
	$(call go_install,ffuf,github.com/ffuf/ffuf/v2@latest)
	$(call go_install,gobuster,github.com/OJ/gobuster/v3@latest)
	$(call go_install,hakrawler,github.com/hakluke/hakrawler@latest)
	$(call go_install,subjs,github.com/lc/subjs@latest)
	$(call go_install,getJS,github.com/003random/getJS@latest)
	$(call go_install,github-subdomains,github.com/gwen001/github-subdomains@latest)
	$(call go_install,puredns,github.com/d3mondev/puredns/v2@latest)
	$(call go_install,shuffledns,github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest)
	@echo "[+] Go tools done."

install-pip-tools:
	@echo "[*] Checking Python tools..."
	$(call pipx_install,wafw00f,wafw00f)
	$(call pipx_install,arjun,arjun)
	$(call pipx_install,paramspider,git+https://github.com/devanshbatham/ParamSpider.git)
	$(call pipx_install,uro,uro)
	$(call pipx_install,sslyze,sslyze)
	$(call pipx_install,dirsearch,dirsearch)
	$(call pipx_install,trufflehog,trufflehog)
	$(call pipx_install,linkfinder,linkfinder)
	$(call pipx_install,corsy,corsy)
	@if command -v SecretFinder >/dev/null 2>&1 || command -v secretfinder >/dev/null 2>&1; then \
		echo "  [ok] secretfinder already installed"; \
	else \
		echo "  [*] Installing secretfinder..."; \
		pipx install git+https://github.com/m4ll0k/SecretFinder.git || echo "  [!] Failed to install secretfinder"; \
	fi
	@echo "[+] Python tools done."

install-apt-tools:
	@echo "[*] Checking apt tools..."
	$(call apt_install,nmap,nmap)
	$(call apt_install,nikto,nikto)
	$(call apt_install,whatweb,whatweb)
	$(call apt_install,wpscan,wpscan)
	$(call apt_install,sqlmap,sqlmap)
	$(call apt_install,commix,commix)
	$(call apt_install,massdns,massdns)
	$(call apt_install,dnsrecon,dnsrecon)
	$(call apt_install,feroxbuster,feroxbuster)
	$(call apt_install,testssl.sh,testssl.sh)
	$(call apt_install,findomain,findomain)
	@echo "[+] Apt tools done."

install-all-tools: install-go-tools install-pip-tools install-apt-tools
	@if ! command -v nuclei >/dev/null 2>&1; then echo "[!] nuclei not found, skipping template update"; else nuclei -update-templates; fi
	@mkdir -p ~/.gf
	@if [ ! -f ~/.gf/xss.json ]; then \
		echo "[*] Installing gf patterns..."; \
		git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true; \
		cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null || true; \
	else \
		echo "  [ok] gf patterns already installed"; \
	fi
	@echo "[+] All done. Run: r0zscope -check"
