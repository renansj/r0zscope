package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	exec2 "os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/runner"
)

// SubdomainEnum performs subdomain enumeration with multiple tools in parallel.
func SubdomainEnum(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	if cfg.CTFMode {
		cyan.Println("\n[PHASE 1] Vhost Brute-Force (CTF local mode)")
		cyan.Println(strings.Repeat("─", 60))
		yellow.Println("  [!] CTF mode active - internet tools disabled")
		yellow.Println("  [!] Using Host header brute-force")

		vhostBruteForce(ctx, cfg, exec)
		return
	}

	cyan.Println("\n[PHASE 1] Subdomain Enumeration")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	var wg sync.WaitGroup
	var outputs []string
	var mu sync.Mutex

	addOutput := func(path string) {
		mu.Lock()
		outputs = append(outputs, path)
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		modStart := time.Now()
		fmt.Println("  [*] subfinder - passive enumeration...")

		outFile := exec.OutputPath("subfinder", "subdomains.txt")
		if alreadyDone(outFile) {
			green.Printf("  [skip] subfinder: output already exists\n")
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "subfinder", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
			return
		}
		args := []string{
			"-d", cfg.Target,
			"-all",
			"-o", outFile,
			"-silent",
		}
		if len(cfg.Resolvers) > 0 {
			args = append(args, "-r", strings.Join(cfg.Resolvers, ","))
		}
		if cfg.Threads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", cfg.Threads))
		}

		_, err := exec.RunCommand(ctx, "subfinder", args, nil)
		lines := runner.CountLines(outFile)

		if err != nil && lines == 0 {
			red.Printf("  [✗] subfinder failed: %v\n", err)
			exec.AddResult(runner.ModuleResult{Module: "subfinder", Success: false, Error: err, Duration: time.Since(modStart)})
			return
		}

		green.Printf("  [✓] subfinder: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
		addOutput(outFile)
		exec.AddResult(runner.ModuleResult{Module: "subfinder", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		modStart := time.Now()
		fmt.Println("  [*] assetfinder - asset discovery...")

		outFile := exec.OutputPath("assetfinder", "subdomains.txt")
		if alreadyDone(outFile) {
			green.Printf("  [skip] assetfinder: output already exists\n")
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "assetfinder", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
			return
		}
		lines, err := exec.RunCommandToFile(ctx, "assetfinder", []string{"--subs-only", cfg.Target}, outFile, nil)

		if err != nil && lines == 0 {
			red.Printf("  [✗] assetfinder failed: %v\n", err)
			exec.AddResult(runner.ModuleResult{Module: "assetfinder", Success: false, Error: err, Duration: time.Since(modStart)})
			return
		}

		green.Printf("  [✓] assetfinder: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
		addOutput(outFile)
		exec.AddResult(runner.ModuleResult{Module: "assetfinder", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
	}()

	if isToolAvailable("amass") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] amass - passive OSINT enum...")

			outFile := exec.OutputPath("amass", "subdomains.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] amass: output already exists\n")
				addOutput(outFile)
				exec.AddResult(runner.ModuleResult{Module: "amass", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{"enum", "-passive", "-d", cfg.Target, "-o", outFile}

			_, err := exec.RunCommand(ctx, "amass", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] amass failed (optional): %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "amass", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] amass: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "amass", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("findomain") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] findomain - fast enumeration (Rust)...")

			outFile := exec.OutputPath("findomain", "subdomains.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] findomain: output already exists\n")
				addOutput(outFile)
				exec.AddResult(runner.ModuleResult{Module: "findomain", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{"-t", cfg.Target, "-u", outFile, "-q"}

			_, err := exec.RunCommand(ctx, "findomain", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] findomain failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "findomain", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] findomain: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "findomain", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		modStart := time.Now()
		fmt.Println("  [*] crt.sh - Certificate Transparency logs...")

		outFile := exec.OutputPath("crtsh", "subdomains.txt")
		if alreadyDone(outFile) {
			green.Printf("  [skip] crtsh: output already exists\n")
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "crt.sh", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
			return
		}
		lines := queryCrtSh(ctx, cfg.Target, outFile)

		if lines == 0 {
			yellow.Printf("  [~] crt.sh: no results\n")
			exec.AddResult(runner.ModuleResult{Module: "crt.sh", Success: false, Duration: time.Since(modStart)})
			return
		}

		green.Printf("  [✓] crt.sh: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
		addOutput(outFile)
		exec.AddResult(runner.ModuleResult{Module: "crt.sh", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
	}()

	if isToolAvailable("github-subdomains") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] github-subdomains - scraping GitHub...")

			outFile := exec.OutputPath("github-subdomains", "subdomains.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] github-subdomains: output already exists\n")
				addOutput(outFile)
				exec.AddResult(runner.ModuleResult{Module: "github-subdomains", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{"-d", cfg.Target, "-o", outFile, "-q"}

			_, err := exec.RunCommand(ctx, "github-subdomains", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] github-subdomains failed (needs GITHUB_TOKEN): %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "github-subdomains", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] github-subdomains: %d subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "github-subdomains", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()

	mergedFile := exec.OutputPath("_merged", "all-subdomains.txt")
	total, err := runner.MergeFiles(mergedFile, outputs...)
	if err != nil {
		red.Printf("  [✗] Merge error: %v\n", err)
		return
	}

	cyan.Printf("\n  [TOTAL] %d unique subdomains found (%v)\n", total, time.Since(start).Round(time.Second))
	fmt.Printf("  └─ %s\n", mergedFile)

	if cfg.SubdomainWordlist != "" {
		bruteForceSubdomains(ctx, cfg, exec, mergedFile)
	}
}

func bruteForceSubdomains(ctx context.Context, cfg *config.Config, exec *runner.Executor, existingFile string) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	if isToolAvailable("puredns") {
		fmt.Println("  [*] puredns - brute-force with wildcard filtering...")
		modStart := time.Now()

		outFile := exec.OutputPath("puredns", "bruteforce.txt")
		args := []string{
			"bruteforce", cfg.SubdomainWordlist, cfg.Target,
			"-w", outFile,
			"-q",
		}
		if len(cfg.Resolvers) > 0 {
			args = append(args, "-r", cfg.Resolvers[0])
		}

		_, err := exec.RunCommand(ctx, "puredns", args, nil)
		lines := runner.CountLines(outFile)

		if err == nil && lines > 0 {
			green.Printf("  [✓] puredns brute: %d new subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
			runner.MergeFiles(existingFile, existingFile, outFile)
			exec.AddResult(runner.ModuleResult{Module: "puredns-brute", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}
	} else if isToolAvailable("shuffledns") && isToolAvailable("massdns") {
		fmt.Println("  [*] shuffledns - subdomain brute-force...")
		modStart := time.Now()

		outFile := exec.OutputPath("shuffledns", "bruteforce.txt")
		args := []string{
			"-d", cfg.Target,
			"-w", cfg.SubdomainWordlist,
			"-o", outFile,
			"-silent",
		}
		if len(cfg.Resolvers) > 0 {
			args = append(args, "-r", cfg.Resolvers[0])
		}

		_, err := exec.RunCommand(ctx, "shuffledns", args, nil)
		lines := runner.CountLines(outFile)

		if err == nil && lines > 0 {
			green.Printf("  [✓] shuffledns brute: %d new subdomains (%v)\n", lines, time.Since(modStart).Round(time.Second))
			runner.MergeFiles(existingFile, existingFile, outFile)
			exec.AddResult(runner.ModuleResult{Module: "shuffledns-brute", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}
	} else {
		yellow.Println("  [~] No DNS brute-force tool available (puredns/shuffledns).")
	}
}

func queryCrtSh(ctx context.Context, domain, outputPath string) int {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "r0zscope/2.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}

	seen := make(map[string]struct{})
	var subs []string

	content := string(body)
	for _, field := range []string{"common_name", "name_value"} {
		searchKey := fmt.Sprintf(`"%s":"`, field)
		idx := 0
		for {
			pos := strings.Index(content[idx:], searchKey)
			if pos == -1 {
				break
			}
			start := idx + pos + len(searchKey)
			end := strings.Index(content[start:], `"`)
			if end == -1 {
				break
			}

			value := content[start : start+end]
			for _, sub := range strings.Split(value, "\\n") {
				sub = strings.TrimSpace(sub)
				sub = strings.TrimPrefix(sub, "*.")
				if sub != "" && strings.HasSuffix(sub, "."+domain) || sub == domain {
					if _, exists := seen[sub]; !exists {
						seen[sub] = struct{}{}
						subs = append(subs, sub)
					}
				}
			}
			idx = start + end
		}
	}

	if len(subs) > 0 {
		writeLines(outputPath, subs)
	}
	return len(subs)
}

func vhostBruteForce(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan, color.Bold)

	start := time.Now()

	vhostWordlist := cfg.VhostWordlist
	if vhostWordlist == "" {
		vhostWordlist = cfg.SubdomainWordlist
	}

	if vhostWordlist == "" {
		defaults := []string{
			"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
			"/usr/share/seclists/Discovery/DNS/namelist.txt",
			"/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
			"/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
			"/usr/share/wordlists/dirb/common.txt",
		}
		for _, wl := range defaults {
			if _, err := os.Stat(wl); err == nil {
				vhostWordlist = wl
				break
			}
		}
	}

	if vhostWordlist == "" {
		red.Println("  [✗] No wordlist found for vhost brute-force.")
		yellow.Println("      Use -wordlist or -vhost-wordlist, or install seclists: apt install -y seclists")
		return
	}

	fmt.Printf("  [*] Wordlist: %s\n", vhostWordlist)

	hasFfuf := isToolAvailable("ffuf")
	hasGobuster := isToolAvailable("gobuster")

	if !hasFfuf && !hasGobuster {
		red.Println("  [✗] ffuf or gobuster required for vhost brute-force. Install: go install github.com/ffuf/ffuf/v2@latest")
		return
	}

	targetURL := fmt.Sprintf("http://%s", cfg.Target)
	if isToolAvailable("curl") {
		output, err := exec.RunCommand(ctx, "curl", []string{
			"-sI", "--max-time", "5", fmt.Sprintf("https://%s", cfg.Target),
		}, nil)
		if err == nil && len(output) > 0 && strings.Contains(string(output), "HTTP/") {
			targetURL = fmt.Sprintf("https://%s", cfg.Target)
		}
	}

	fmt.Printf("  [*] Target URL: %s\n", targetURL)
	fmt.Printf("  [*] Host header: FUZZ.%s\n", cfg.Target)

	outFile := exec.OutputPath("vhost-brute", "vhosts.txt")
	outRaw := exec.OutputPath("vhost-brute", "raw-output.txt")

	if hasFfuf {
		fmt.Println("  [*] ffuf - vhost brute-force via Host header...")

		args := []string{
			"-w", vhostWordlist,
			"-u", targetURL,
			"-H", fmt.Sprintf("Host: FUZZ.%s", cfg.Target),
			"-o", outRaw,
			"-of", "csv",
			"-ac",
			"-t", fmt.Sprintf("%d", cfg.Threads),
			"-timeout", "10",
			"-s",
		}

		if cfg.RateLimit > 0 {
			args = append(args, "-rate", fmt.Sprintf("%d", cfg.RateLimit))
		}

		_, err := exec.RunCommand(ctx, "ffuf", args, nil)
		lines := runner.CountLines(outRaw)

		if err != nil && lines == 0 {
			yellow.Printf("  [~] ffuf vhost: no vhosts found (%v)\n", time.Since(start).Round(time.Second))
		}

		vhosts := extractFfufVhosts(outRaw, cfg.Target)
		if len(vhosts) > 0 {
			writeLines(outFile, vhosts)
			green.Printf("  [✓] ffuf vhost: %d vhosts found!\n", len(vhosts))
			for _, vh := range vhosts {
				green.Printf("      → %s\n", vh)
			}
		}

	} else if hasGobuster {
		fmt.Println("  [*] gobuster - vhost brute-force...")

		args := []string{
			"vhost",
			"-u", targetURL,
			"-w", vhostWordlist,
			"-o", outFile,
			"-t", fmt.Sprintf("%d", cfg.Threads),
			"--timeout", "10s",
			"--no-error",
			"--append-domain",
		}

		_, err := exec.RunCommand(ctx, "gobuster", args, nil)
		lines := runner.CountLines(outFile)

		if err == nil && lines > 0 {
			green.Printf("  [✓] gobuster vhost: %d vhosts found!\n", lines)
		}
	}

	mergedFile := exec.OutputPath("_merged", "all-subdomains.txt")
	vhosts := readLines(outFile)

	allSubs := []string{cfg.Target}
	allSubs = append(allSubs, vhosts...)
	writeLines(mergedFile, allSubs)

	total := len(allSubs)
	cyan.Printf("\n  [TOTAL] %d hosts (1 main + %d vhosts) (%v)\n", total, total-1, time.Since(start).Round(time.Second))
	fmt.Printf("  └─ %s\n", mergedFile)

	exec.AddResult(runner.ModuleResult{Module: "vhost-brute", Success: true, OutputDir: outFile, Lines: total, Duration: time.Since(start)})
}

func extractFfufVhosts(csvPath, domain string) []string {
	lines := readLines(csvPath)
	var vhosts []string
	seen := make(map[string]struct{})

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			fuzz := strings.TrimSpace(parts[0])
			if fuzz == "FUZZ" || fuzz == "" || fuzz == "input" {
				continue
			}
			vhost := fmt.Sprintf("%s.%s", fuzz, domain)
			if _, exists := seen[vhost]; !exists {
				seen[vhost] = struct{}{}
				vhosts = append(vhosts, vhost)
			}
		}
	}

	return vhosts
}

func isToolAvailable(name string) bool {
	_, err := exec2.LookPath(name)
	return err == nil
}
