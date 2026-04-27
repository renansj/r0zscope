package modules

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/runner"
)

// VulnScan performs vulnerability scanning with multiple tools.
func VulnScan(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 8] Vulnerability Scanning")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")
	paramURLs := exec.OutputPath("_merged", "urls-with-params.txt")

	if !runner.FileExists(aliveFile) {
		aliveFile = exec.OutputPath("_merged", "all-subdomains.txt")
		if !runner.FileExists(aliveFile) {
			yellow.Println("  [~] No alive hosts found. Skipping.")
			return
		}
		yellow.Println("  [~] Using subdomain list (no prior probe).")
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		modStart := time.Now()

		fmt.Println("  [*] nuclei - updating templates...")
		exec.RunCommand(ctx, "nuclei", []string{"-update-templates", "-silent"}, nil)

		fmt.Println("  [*] nuclei - main scan...")
		outFile := exec.OutputPath("nuclei", "findings.txt")

		args := []string{
			"-l", aliveFile,
			"-o", outFile,
			"-silent",
			"-c", fmt.Sprintf("%d", cfg.Threads),
			"-timeout", "10",
			"-retries", "2",
			"-bulk-size", "50",
			"-rate-limit", "150",
		}
		if cfg.NucleiSeverity != "" {
			args = append(args, "-severity", cfg.NucleiSeverity)
		}
		if cfg.NucleiTemplatesPath != "" {
			args = append(args, "-t", cfg.NucleiTemplatesPath)
		}
		if cfg.Proxy != "" {
			args = append(args, "-proxy", cfg.Proxy)
		}

		_, err := exec.RunCommand(ctx, "nuclei", args, nil)
		lines := runner.CountLines(outFile)

		if err != nil && lines == 0 {
			red.Printf("  [✗] nuclei failed: %v\n", err)
			exec.AddResult(runner.ModuleResult{Module: "nuclei", Success: false, Error: err, Duration: time.Since(modStart)})
			return
		}

		if lines > 0 {
			color.New(color.FgRed, color.Bold).Printf("  [!!!] nuclei: %d vulnerabilities found!\n", lines)
		} else {
			green.Printf("  [✓] nuclei: no vulnerabilities found (%v)\n", time.Since(modStart).Round(time.Second))
		}
		exec.AddResult(runner.ModuleResult{Module: "nuclei", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})

		if runner.FileExists(paramURLs) {
			fmt.Println("  [*] nuclei - fuzzing URLs with parameters...")
			fuzzOutFile := exec.OutputPath("nuclei", "fuzz-findings.txt")
			fuzzArgs := []string{
				"-l", paramURLs,
				"-o", fuzzOutFile,
				"-t", "http/cves/,http/vulnerabilities/,http/exposures/",
				"-silent",
				"-c", fmt.Sprintf("%d", cfg.Threads/2),
				"-timeout", "10",
				"-rate-limit", "100",
			}
			if cfg.Proxy != "" {
				fuzzArgs = append(fuzzArgs, "-proxy", cfg.Proxy)
			}

			exec.RunCommand(ctx, "nuclei", fuzzArgs, nil)
			fuzzLines := runner.CountLines(fuzzOutFile)
			if fuzzLines > 0 {
				color.New(color.FgRed, color.Bold).Printf("  [!!!] nuclei fuzz: %d additional findings!\n", fuzzLines)
			}
		}
	}()

	if isToolAvailable("nikto") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] nikto - classic web scanner...")

			aliveURLs := readLines(aliveFile)
			limit := 5
			if len(aliveURLs) < limit {
				limit = len(aliveURLs)
			}

			var allResults []string
			var mu sync.Mutex
			sem := make(chan struct{}, 3)
			var nwg sync.WaitGroup

			for _, url := range aliveURLs[:limit] {
				cleanURL := strings.Fields(url)[0]
				if !strings.HasPrefix(cleanURL, "http") {
					cleanURL = "https://" + cleanURL
				}

				nwg.Add(1)
				go func(u string) {
					defer nwg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					output, err := exec.RunCommand(ctx, "nikto",
						[]string{"-h", u, "-Tuning", "1234567890abc", "-timeout", "10", "-nointeractive"}, nil)
					if err == nil && len(output) > 0 {
						mu.Lock()
						allResults = append(allResults, fmt.Sprintf("=== %s ===", u))
						allResults = append(allResults, string(output))
						mu.Unlock()
					}
				}(cleanURL)
			}
			nwg.Wait()

			outFile := exec.OutputPath("nikto", "findings.txt")
			if len(allResults) > 0 {
				writeLines(outFile, allResults)
			}

			lines := runner.CountLines(outFile)
			green.Printf("  [✓] nikto: %d hosts analyzed (%v)\n", limit, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "nikto", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("dalfox") && runner.FileExists(paramURLs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] dalfox - XSS scanning...")

			outFile := exec.OutputPath("dalfox", "xss-findings.txt")
			args := []string{
				"file", paramURLs,
				"-o", outFile,
				"-w", fmt.Sprintf("%d", cfg.Threads),
				"--silence",
				"--no-color",
				"--timeout", "10",
			}
			if cfg.Proxy != "" {
				args = append(args, "--proxy", cfg.Proxy)
			}

			_, err := exec.RunCommand(ctx, "dalfox", args, nil)
			lines := runner.CountLines(outFile)

			if lines > 0 {
				color.New(color.FgRed, color.Bold).Printf("  [!!!] dalfox: %d XSS found!\n", lines)
			} else {
				green.Printf("  [✓] dalfox: no XSS found (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "dalfox", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("sqlmap") && runner.FileExists(paramURLs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] sqlmap - SQL injection scanning (batch)...")

			outDir := exec.ModuleDir("sqlmap")
			exec.EnsureDir(outDir)

			urls := readLines(paramURLs)
			limit := 20
			if len(urls) < limit {
				limit = len(urls)
			}

			var findings []string
			for _, url := range urls[:limit] {
				cleanURL := strings.Fields(url)[0]

				output, err := exec.RunCommand(ctx, "sqlmap",
					[]string{
						"-u", cleanURL,
						"--batch",
						"--level", "1",
						"--risk", "1",
						"--timeout", "10",
						"--retries", "1",
						"--threads", "3",
						"--output-dir", outDir,
						"--smart",
					}, nil)

				if err == nil && len(output) > 0 {
					outStr := string(output)
					if strings.Contains(outStr, "is vulnerable") || strings.Contains(outStr, "injectable") {
						findings = append(findings, fmt.Sprintf("[VULN] %s", cleanURL))
						findings = append(findings, outStr)
					}
				}
			}

			outFile := exec.OutputPath("sqlmap", "findings.txt")
			if len(findings) > 0 {
				writeLines(outFile, findings)
				color.New(color.FgRed, color.Bold).Printf("  [!!!] sqlmap: SQL injection found!\n")
			} else {
				green.Printf("  [✓] sqlmap: no SQLi found (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "sqlmap", Success: true, OutputDir: outDir, Lines: len(findings), Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("crlfuzz") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] crlfuzz - CRLF injection scanning...")

			outFile := exec.OutputPath("crlfuzz", "findings.txt")
			args := []string{
				"-l", aliveFile,
				"-o", outFile,
				"-c", fmt.Sprintf("%d", cfg.Threads),
				"-s",
			}

			_, err := exec.RunCommand(ctx, "crlfuzz", args, nil)
			lines := runner.CountLines(outFile)

			if lines > 0 {
				color.New(color.FgRed, color.Bold).Printf("  [!!!] crlfuzz: %d CRLF injections found!\n", lines)
			} else {
				green.Printf("  [✓] crlfuzz: no CRLF found (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "crlfuzz", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("corsy") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] corsy - CORS misconfiguration scanning...")

			outFile := exec.OutputPath("corsy", "findings.json")
			args := []string{
				"-i", aliveFile,
				"-o", outFile,
				"-t", fmt.Sprintf("%d", cfg.Threads),
			}

			_, err := exec.RunCommand(ctx, "corsy", args, nil)
			lines := runner.CountLines(outFile)

			if lines > 0 {
				color.New(color.FgRed, color.Bold).Printf("  [!!!] corsy: CORS misconfiguration found!\n")
			} else {
				green.Printf("  [✓] corsy: no CORS issues (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "corsy", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("wpscan") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()

			wpHosts := detectWordPress(exec)
			if len(wpHosts) == 0 {
				aliveURLs := readLines(aliveFile)
				limit := 5
				if len(aliveURLs) < limit {
					limit = len(aliveURLs)
				}
				wpHosts = aliveURLs[:limit]
			}

			if len(wpHosts) == 0 {
				return
			}

			fmt.Printf("  [*] wpscan - scanning %d WordPress hosts...\n", len(wpHosts))

			var allResults []string
			for _, url := range wpHosts {
				cleanURL := strings.Fields(url)[0]
				if !strings.HasPrefix(cleanURL, "http") {
					cleanURL = "https://" + cleanURL
				}

				output, err := exec.RunCommand(ctx, "wpscan",
					[]string{
						"--url", cleanURL,
						"--enumerate", "vp,vt,u",
						"--detection-mode", "aggressive",
						"--no-banner",
						"--format", "cli",
					}, nil)

				if err == nil && len(output) > 0 {
					allResults = append(allResults, fmt.Sprintf("=== %s ===", cleanURL))
					allResults = append(allResults, string(output))
				}
			}

			outFile := exec.OutputPath("wpscan", "findings.txt")
			if len(allResults) > 0 {
				writeLines(outFile, allResults)
				green.Printf("  [✓] wpscan: %d hosts analyzed (%v)\n", len(wpHosts), time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "wpscan", Success: true, OutputDir: outFile, Lines: len(allResults), Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("commix") && runner.FileExists(paramURLs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] commix - command injection scanning...")

			urls := readLines(paramURLs)
			limit := 10
			if len(urls) < limit {
				limit = len(urls)
			}

			var findings []string
			for _, url := range urls[:limit] {
				cleanURL := strings.Fields(url)[0]

				output, err := exec.RunCommand(ctx, "commix",
					[]string{
						"--url", cleanURL,
						"--batch",
						"--level", "1",
						"--timeout", "10",
					}, nil)

				if err == nil && len(output) > 0 {
					outStr := string(output)
					if strings.Contains(outStr, "is vulnerable") {
						findings = append(findings, fmt.Sprintf("[VULN] %s", cleanURL))
					}
				}
			}

			outFile := exec.OutputPath("commix", "findings.txt")
			if len(findings) > 0 {
				writeLines(outFile, findings)
				color.New(color.FgRed, color.Bold).Printf("  [!!!] commix: command injection found!\n")
			} else {
				green.Printf("  [✓] commix: no CMDi found (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "commix", Success: true, OutputDir: outFile, Lines: len(findings), Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] Vulnerability scan completed (%v)\n", time.Since(start).Round(time.Second))
}

func detectWordPress(exec *runner.Executor) []string {
	var wpHosts []string

	whatwebFile := exec.OutputPath("whatweb", "fingerprint.txt")
	if runner.FileExists(whatwebFile) {
		lines := readLines(whatwebFile)
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "wordpress") || strings.Contains(lower, "wp-") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					wpHosts = append(wpHosts, parts[0])
				}
			}
		}
	}

	return wpHosts
}
