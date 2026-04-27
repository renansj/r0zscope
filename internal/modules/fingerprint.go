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

// Fingerprint performs WAF detection and technology fingerprinting.
func Fingerprint(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 3.5] WAF Detection & Fingerprinting")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")

	if !runner.FileExists(aliveFile) {
		yellow.Println("  [~] No alive hosts found. Skipping.")
		return
	}

	var wg sync.WaitGroup

	if isToolAvailable("wafw00f") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] wafw00f - WAF detection...")

			outFile := exec.OutputPath("wafw00f", "waf-results.txt")
			aliveURLs := readLines(aliveFile)

			var results []string
			limit := 50
			if len(aliveURLs) < limit {
				limit = len(aliveURLs)
			}

			for _, url := range aliveURLs[:limit] {
				cleanURL := strings.Fields(url)[0]
				if !strings.HasPrefix(cleanURL, "http") {
					cleanURL = "https://" + cleanURL
				}

				output, err := exec.RunCommand(ctx, "wafw00f", []string{cleanURL, "-o", "-"}, nil)
				if err == nil && len(output) > 0 {
					results = append(results, fmt.Sprintf("%s: %s", cleanURL, strings.TrimSpace(string(output))))
				}
			}

			if len(results) > 0 {
				writeLines(outFile, results)
			}

			lines := len(results)
			green.Printf("  [✓] wafw00f: %d hosts analyzed (%v)\n", lines, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "wafw00f", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if isToolAvailable("whatweb") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] whatweb - web fingerprinting...")

			outFile := exec.OutputPath("whatweb", "fingerprint.txt")
			args := []string{
				"-i", aliveFile,
				"--log-brief", outFile,
				"-t", fmt.Sprintf("%d", cfg.Threads),
				"--no-errors",
				"-q",
			}

			_, err := exec.RunCommand(ctx, "whatweb", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] whatweb failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "whatweb", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] whatweb: %d hosts fingerprinted (%v)\n", lines, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "whatweb", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()

	if !isToolAvailable("wafw00f") && !isToolAvailable("whatweb") {
		yellow.Println("  [~] No fingerprinting tools available (wafw00f, whatweb).")
	}

	cyan.Printf("  [TOTAL] Fingerprinting completed (%v)\n", time.Since(start).Round(time.Second))
}
