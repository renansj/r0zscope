package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/modules"
	"github.com/renansj/r0zscope/internal/runner"
)

var (
	version = "dev"
	commit  = "none"
)

const banner = `

   ██████╗  ██████╗ ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
   ██╔══██╗██╔═══██╗╚══███╔╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ██████╔╝██║   ██║  ███╔╝ ███████╗██║     ██║   ██║██████╔╝█████╗  
   ██╔══██╗██║   ██║ ███╔╝  ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
   ██║  ██║╚██████╔╝███████╗███████║╚██████╗╚██████╔╝██║     ███████╗
   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝

   By R0Z (Renan Zapelini)
`

func printBanner() {
	cyan := color.New(color.FgCyan)
	cyan.Print(banner)
	fmt.Printf("   Version: %s (%s)\n\n", version, commit)
}

func main() {
	target := flag.String("target", "", "Target domain (required)")
	configFile := flag.String("config", "", "YAML config file")
	outputDir := flag.String("output", "", "Output directory (default: recon-output/<target>)")
	threads := flag.Int("threads", 0, "Thread count (default: auto)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	proxy := flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
	severity := flag.String("severity", "critical,high,medium", "Nuclei severity filter")
	crawlDepth := flag.Int("depth", 3, "Crawl depth")
	rateLimit := flag.Int("rate-limit", 0, "Global rate limit (req/s, 0 = unlimited)")
	wordlist := flag.String("wordlist", "", "Wordlist for subdomain brute-force")
	vhostWordlist := flag.String("vhost-wordlist", "", "Wordlist for vhost brute-force (CTF mode)")
	ctfMode := flag.Bool("ctf", false, "CTF mode - local target via /etc/hosts, vhost brute-force, no internet tools")
	showVersion := flag.Bool("version", false, "Show version and exit")
	checkOnly := flag.Bool("check", false, "Check installed tools only")
	installScript := flag.Bool("install-script", false, "Generate install script")
	installMissing := flag.Bool("install", false, "Install missing tools")
	genConfig := flag.String("gen-config", "", "Generate example config file")
	skipPhases := flag.String("skip", "", "Phases to skip (comma-separated)")
	onlyPhases := flag.String("only", "", "Run only these phases (comma-separated)")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage: r0zscope -target <domain> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Phases (execution order):
  subdomains    Subdomain enumeration
  dns           DNS resolution & enumeration
  httpprobe     HTTP probing
  fingerprint   WAF detection & fingerprinting
  portscan      Port scanning
  urls          URL discovery
  content       Directory/content discovery
  jsanalysis    JavaScript analysis on local files
  takeover      Subdomain takeover
  vulnscan      Vulnerability scanning
  ssl           SSL/TLS analysis

Examples:
  r0zscope -target example.com
  r0zscope -target example.com -threads 30 -verbose
  r0zscope -target example.com -proxy http://127.0.0.1:8080
  r0zscope -target example.com -only subdomains,httpprobe,vulnscan
  r0zscope -target example.com -skip portscan,ssl,content
  r0zscope -target test.htb -ctf
  r0zscope -check
  r0zscope -install
`)
	}

	flag.Parse()

	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	printBanner()

	if *showVersion {
		os.Exit(0)
	}

	if *genConfig != "" {
		if err := config.SaveExample(*genConfig); err != nil {
			red.Printf("[-] Failed to generate config: %v\n", err)
			os.Exit(1)
		}
		green.Printf("[+] Example config generated: %s\n", *genConfig)
		os.Exit(0)
	}

	toolResults := runner.CheckTools()
	runner.PrintToolStatus(toolResults)

	if *checkOnly {
		missing := runner.GetMissingRequired(toolResults)
		if len(missing) > 0 {
			red.Printf("[-] %d required tools missing.\n", len(missing))
			os.Exit(1)
		}
		green.Println("[+] All required tools are installed.")
		os.Exit(0)
	}

	if *installScript {
		allMissing := append(runner.GetMissingRequired(toolResults), runner.GetMissingOptional(toolResults)...)
		if len(allMissing) == 0 {
			green.Println("[+] All tools already installed.")
			os.Exit(0)
		}
		script := runner.GenerateInstallScript(allMissing)
		scriptPath := "install-tools.sh"
		os.WriteFile(scriptPath, []byte(script), 0755)
		green.Printf("[+] Script generated: %s (%d tools)\n", scriptPath, len(allMissing))
		os.Exit(0)
	}

	if *installMissing {
		installTools(toolResults)
		os.Exit(0)
	}

	missingRequired := runner.GetMissingRequired(toolResults)
	if len(missingRequired) > 0 {
		red.Println("[-] Required tools missing:")
		for _, m := range missingRequired {
			fmt.Printf("    - %s: %s\n", m.Tool.Name, m.Tool.Description)
		}
		fmt.Println()
		yellow.Println("[?] Install missing tools? (y/n)")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "y" || answer == "yes" {
			installTools(toolResults)
			toolResults = runner.CheckTools()
			missingRequired = runner.GetMissingRequired(toolResults)
			if len(missingRequired) > 0 {
				red.Println("[-] Some tools still missing. Check manually.")
				os.Exit(1)
			}
		} else {
			red.Println("[-] Cannot continue without required tools.")
			os.Exit(1)
		}
	}

	if *target == "" {
		red.Println("[-] No target specified.")
		red.Println("    Usage: r0zscope -target <domain> [options]")
		flag.Usage()
		os.Exit(1)
	}

	var cfg *config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.LoadFromFile(*configFile)
		if err != nil {
			red.Printf("[-] Failed to load config: %v\n", err)
			os.Exit(1)
		}
		cfg.Target = *target
	} else {
		cfg = config.DefaultConfig(*target)
	}

	if *outputDir != "" {
		cfg.OutputDir = *outputDir
	}
	if *threads > 0 {
		cfg.Threads = *threads
	}
	if *verbose {
		cfg.Verbose = true
	}
	if *proxy != "" {
		cfg.Proxy = *proxy
	}
	if *severity != "" {
		cfg.NucleiSeverity = *severity
	}
	if *crawlDepth > 0 {
		cfg.CrawlDepth = *crawlDepth
	}
	if *rateLimit > 0 {
		cfg.RateLimit = *rateLimit
	}
	if *wordlist != "" {
		cfg.SubdomainWordlist = *wordlist
	}
	if *vhostWordlist != "" {
		cfg.VhostWordlist = *vhostWordlist
	}
	if *ctfMode {
		cfg.CTFMode = true
	}

	skipSet := parsePhaseList(*skipPhases)
	onlySet := parsePhaseList(*onlyPhases)

	shouldRun := func(phase string) bool {
		if len(onlySet) > 0 {
			_, ok := onlySet[phase]
			return ok
		}
		_, skip := skipSet[phase]
		return !skip
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		yellow.Println("\n[!] Interrupt received. Shutting down gracefully...")
		cancel()
	}()

	totalStart := time.Now()
	e := runner.NewExecutor(cfg)

	green.Printf("[+] Starting recon on: %s\n", cfg.Target)
	fmt.Printf("    Output:  %s\n", cfg.OutputDir)
	fmt.Printf("    Threads: %d\n", cfg.Threads)
	if cfg.CTFMode {
		color.New(color.FgYellow, color.Bold).Println("    Mode:    CTF LOCAL (internet tools disabled)")
	}
	if cfg.Proxy != "" {
		fmt.Printf("    Proxy:   %s\n", cfg.Proxy)
	}

	os.MkdirAll(cfg.OutputDir, 0755)

	// ── STAGE 1: Subdomain enumeration (must run first) ──
	if shouldRun("subdomains") {
		modules.SubdomainEnum(ctx, cfg, e)
		if ctx.Err() != nil {
			goto report
		}
	}

	// ── STAGE 2: DNS + HTTP probe in parallel (both need subdomains) ──
	{
		var wg sync.WaitGroup
		if shouldRun("dns") && !cfg.CTFMode {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.DNSResolution(ctx, cfg, e)
			}()
		}
		if shouldRun("httpprobe") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.HTTPProbe(ctx, cfg, e)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			goto report
		}
	}

	// ── STAGE 3: Everything that needs alive hosts, in parallel ──
	{
		var wg sync.WaitGroup

		if shouldRun("fingerprint") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.Fingerprint(ctx, cfg, e)
			}()
		}
		if shouldRun("portscan") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.PortScan(ctx, cfg, e)
			}()
		}
		if shouldRun("takeover") && !cfg.CTFMode {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.SubdomainTakeover(ctx, cfg, e)
			}()
		}
		if shouldRun("ssl") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.SSLAnalysis(ctx, cfg, e)
			}()
		}
		if shouldRun("urls") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.URLDiscovery(ctx, cfg, e)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			goto report
		}
	}

	// ── STAGE 4: Content discovery + JS analysis + vuln scan in parallel (need URLs) ──
	{
		var wg sync.WaitGroup

		if shouldRun("content") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.ContentDiscovery(ctx, cfg, e)
			}()
		}
		if shouldRun("jsanalysis") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.JSAnalysis(ctx, cfg, e)
			}()
		}
		if shouldRun("vulnscan") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				modules.VulnScan(ctx, cfg, e)
			}()
		}
		wg.Wait()
	}

report:
	modules.GenerateReport(cfg, e, totalStart)
	green.Println("[+] Recon finished.")
}

func parsePhaseList(s string) map[string]struct{} {
	result := make(map[string]struct{})
	if s == "" {
		return result
	}
	for _, phase := range strings.Split(s, ",") {
		phase = strings.TrimSpace(phase)
		if phase != "" {
			result[phase] = struct{}{}
		}
	}
	return result
}

func installTools(results []runner.CheckResult) {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	allMissing := append(runner.GetMissingRequired(results), runner.GetMissingOptional(results)...)
	if len(allMissing) == 0 {
		green.Println("[+] All tools already installed.")
		return
	}

	fmt.Printf("[*] Installing %d tools...\n\n", len(allMissing))

	for _, m := range allMissing {
		if m.Tool.GoInstall == "" {
			yellow.Printf("  [~] %s: manual install required\n", m.Tool.Name)
			fmt.Printf("      %s\n", m.Tool.InstallCmd)
			continue
		}

		fmt.Printf("  [*] Installing %s...\n", m.Tool.Name)
		cmd := fmt.Sprintf("go install -v %s", m.Tool.GoInstall)
		parts := strings.Fields(cmd)

		proc := &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}}
		goPath, err := exec.LookPath(parts[0])
		if err != nil {
			red.Printf("  [✗] go not found: %v\n", err)
			continue
		}

		process, err := os.StartProcess(goPath, parts, proc)
		if err != nil {
			red.Printf("  [✗] Failed to install %s: %v\n", m.Tool.Name, err)
			continue
		}

		state, err := process.Wait()
		if err != nil || !state.Success() {
			red.Printf("  [✗] Failed to install %s\n", m.Tool.Name)
			continue
		}

		green.Printf("  [✓] %s installed\n", m.Tool.Name)
	}
	fmt.Println()
}
