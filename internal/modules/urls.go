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

// URLDiscovery collects URLs from multiple sources in parallel.
func URLDiscovery(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	cyan.Println("\n[PHASE 5] URL Discovery")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")
	subsFile := exec.OutputPath("_merged", "all-subdomains.txt")

	if !runner.FileExists(subsFile) {
		yellow.Println("  [~] No subdomains found. Skipping.")
		return
	}

	var wg sync.WaitGroup
	var outputs []string
	var mu sync.Mutex

	addOutput := func(path string) {
		mu.Lock()
		outputs = append(outputs, path)
		mu.Unlock()
	}

	if !cfg.CTFMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] waybackurls - historical URLs...")

			outFile := exec.OutputPath("waybackurls", "urls.txt")
			lines, err := exec.RunCommandToFile(ctx, "waybackurls", []string{cfg.Target}, outFile, nil)

			if err != nil && lines == 0 {
				red.Printf("  [✗] waybackurls failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "waybackurls", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] waybackurls: %d URLs (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "waybackurls", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("gau") && !cfg.CTFMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] gau - AlienVault, Wayback, Common Crawl...")

			outFile := exec.OutputPath("gau", "urls.txt")
			args := []string{
				"--threads", fmt.Sprintf("%d", cfg.Threads),
				"--o", outFile,
				cfg.Target,
			}

			_, err := exec.RunCommand(ctx, "gau", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] gau failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "gau", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] gau: %d URLs (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "gau", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if runner.FileExists(aliveFile) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] katana - active crawling with JS parsing + response download...")

			outFile := exec.OutputPath("katana", "urls.txt")
			jsStoreDir := exec.OutputPath("katana", "js-responses")
			exec.EnsureDir(jsStoreDir)

			args := []string{
				"-list", aliveFile,
				"-o", outFile,
				"-d", fmt.Sprintf("%d", cfg.CrawlDepth),
				"-jc",
				"-kf", "all",
				"-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
				"-silent",
				"-c", fmt.Sprintf("%d", cfg.Threads),
				"-timeout", "10",
				"-store-response",
				"-store-response-dir", jsStoreDir,
			}
			if cfg.InScope {
				args = append(args, "-fs", "fqdn")
			}

			_, err := exec.RunCommand(ctx, "katana", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				red.Printf("  [✗] katana failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "katana", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] katana: %d URLs (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "katana", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("gospider") && runner.FileExists(aliveFile) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] gospider - web spider...")

			outDir := exec.ModuleDir("gospider")
			exec.EnsureDir(outDir)

			args := []string{
				"-S", aliveFile,
				"-o", outDir,
				"-d", fmt.Sprintf("%d", cfg.CrawlDepth),
				"-c", fmt.Sprintf("%d", cfg.Threads),
				"-t", "10",
				"--js", "--sitemap", "--robots",
				"-q",
			}

			_, err := exec.RunCommand(ctx, "gospider", args, nil)
			consolidatedFile := exec.OutputPath("gospider", "all-urls.txt")
			lines := consolidateGoSpiderOutput(outDir, consolidatedFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] gospider failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "gospider", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] gospider: %d URLs (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(consolidatedFile)
			exec.AddResult(runner.ModuleResult{Module: "gospider", Success: true, OutputDir: consolidatedFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("hakrawler") && runner.FileExists(aliveFile) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] hakrawler - fast crawler...")

			outFile := exec.OutputPath("hakrawler", "urls.txt")
			args := []string{
				"-d", fmt.Sprintf("%d", cfg.CrawlDepth),
				"-t", fmt.Sprintf("%d", cfg.Threads),
				"-subs",
				"-insecure",
			}

			lines, err := exec.RunCommandToFile(ctx, "hakrawler", args, outFile, openFileAsReader(aliveFile))

			if err != nil && lines == 0 {
				yellow.Printf("  [~] hakrawler failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "hakrawler", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] hakrawler: %d URLs (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "hakrawler", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("paramspider") && !cfg.CTFMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] paramspider - parameter mining...")

			outFile := exec.OutputPath("paramspider", "urls.txt")
			args := []string{
				"-d", cfg.Target,
				"-o", outFile,
			}

			_, err := exec.RunCommand(ctx, "paramspider", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] paramspider failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "paramspider", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] paramspider: %d URLs with params (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "paramspider", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()

	mergedFile := exec.OutputPath("_merged", "all-urls.txt")
	total, err := runner.MergeFiles(mergedFile, outputs...)
	if err != nil {
		red.Printf("  [✗] Merge error: %v\n", err)
		return
	}

	if isToolAvailable("uro") {
		fmt.Println("  [*] uro - smart URL deduplication...")
		dedupFile := exec.OutputPath("_merged", "all-urls-dedup.txt")
		exec.RunCommandToFile(ctx, "uro", []string{"-i", mergedFile}, dedupFile, nil)
		dedupLines := runner.CountLines(dedupFile)
		if dedupLines > 0 && dedupLines < total {
			green.Printf("  [✓] uro: %d → %d URLs (removed %d similar)\n", total, dedupLines, total-dedupLines)
		}
	}

	cyan.Printf("\n  [TOTAL] %d unique URLs found (%v)\n", total, time.Since(start).Round(time.Second))
	fmt.Printf("  └─ %s\n", mergedFile)

	extractURLComponents(ctx, cfg, exec, mergedFile)
}

func extractURLComponents(ctx context.Context, cfg *config.Config, exec *runner.Executor, urlsFile string) {
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	var wg sync.WaitGroup

	if isToolAvailable("unfurl") {
		fmt.Println("  [*] unfurl - extracting URL components...")

		wg.Add(1)
		go func() {
			defer wg.Done()
			outFile := exec.OutputPath("unfurl", "params.txt")
			exec.RunCommandToFile(ctx, "unfurl", []string{"--unique", "keys"}, outFile, openFileAsReader(urlsFile))
			lines := runner.CountLines(outFile)
			if lines > 0 {
				green.Printf("  [✓] unfurl params: %d unique parameters\n", lines)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			outFile := exec.OutputPath("unfurl", "paths.txt")
			exec.RunCommandToFile(ctx, "unfurl", []string{"--unique", "paths"}, outFile, openFileAsReader(urlsFile))
			lines := runner.CountLines(outFile)
			if lines > 0 {
				green.Printf("  [✓] unfurl paths: %d unique paths\n", lines)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			outFile := exec.OutputPath("unfurl", "domains.txt")
			exec.RunCommandToFile(ctx, "unfurl", []string{"--unique", "domains"}, outFile, openFileAsReader(urlsFile))
			lines := runner.CountLines(outFile)
			if lines > 0 {
				green.Printf("  [✓] unfurl domains: %d unique domains\n", lines)
			}
		}()
	}

	if isToolAvailable("gf") {
		patterns := []string{"xss", "sqli", "ssrf", "redirect", "rce", "lfi", "idor", "ssti"}
		for _, pattern := range patterns {
			p := pattern
			wg.Add(1)
			go func() {
				defer wg.Done()
				outFile := exec.OutputPath("gf", fmt.Sprintf("%s.txt", p))
				exec.RunCommandToFile(ctx, "gf", []string{p}, outFile, openFileAsReader(urlsFile))
				lines := runner.CountLines(outFile)
				if lines > 0 {
					yellow.Printf("  [!] gf %s: %d potentially vulnerable URLs\n", p, lines)
				}
			}()
		}
	}

	wg.Wait()

	filterParamURLs(urlsFile, exec.OutputPath("_merged", "urls-with-params.txt"))
	filterJSFiles(urlsFile, exec.OutputPath("_merged", "js-files.txt"))

	paramURLs := runner.CountLines(exec.OutputPath("_merged", "urls-with-params.txt"))
	jsFiles := runner.CountLines(exec.OutputPath("_merged", "js-files.txt"))

	if paramURLs > 0 {
		yellow.Printf("  [!] %d URLs with parameters (injection targets)\n", paramURLs)
	}
	if jsFiles > 0 {
		yellow.Printf("  [!] %d JavaScript files found\n", jsFiles)
	}
}
