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

// SSLAnalysis performs SSL/TLS configuration analysis.
func SSLAnalysis(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 9] SSL/TLS Analysis")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")

	hasTestssl := isToolAvailable("testssl") || isToolAvailable("testssl.sh")
	hasSslyze := isToolAvailable("sslyze")

	if !hasTestssl && !hasSslyze {
		yellow.Println("  [~] No SSL analysis tools available (testssl, sslyze). Skipping.")
		return
	}

	if !runner.FileExists(aliveFile) {
		yellow.Println("  [~] No alive hosts found. Skipping.")
		return
	}

	aliveURLs := readLines(aliveFile)
	var httpsHosts []string
	for _, url := range aliveURLs {
		cleanURL := strings.Fields(url)[0]
		if strings.HasPrefix(cleanURL, "https://") {
			host := strings.TrimPrefix(cleanURL, "https://")
			host = strings.Split(host, "/")[0]
			httpsHosts = append(httpsHosts, host)
		}
	}

	if len(httpsHosts) == 0 {
		yellow.Println("  [~] No HTTPS hosts found. Skipping.")
		return
	}

	limit := 5
	if len(httpsHosts) < limit {
		limit = len(httpsHosts)
	}

	fmt.Printf("  [*] Analyzing SSL/TLS on %d hosts...\n", limit)

	var wg sync.WaitGroup

	if hasSslyze {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] sslyze - SSL/TLS analysis...")

			outFile := exec.OutputPath("sslyze", "results.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] sslyze: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "sslyze", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{"--regular"}
			args = append(args, httpsHosts[:limit]...)

			output, err := exec.RunCommand(ctx, "sslyze", args, nil)
			if len(output) > 0 {
				writeLines(outFile, []string{string(output)})
			}

			lines := runner.CountLines(outFile)
			if err == nil {
				green.Printf("  [✓] sslyze: %d hosts analyzed (%v)\n", limit, time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "sslyze", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if hasTestssl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()

			testsslLimit := 3
			if len(httpsHosts) < testsslLimit {
				testsslLimit = len(httpsHosts)
			}

			fmt.Printf("  [*] testssl - deep analysis on %d hosts...\n", testsslLimit)

			outFile := exec.OutputPath("testssl", "results.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] testssl: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "testssl", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}

			var allResults []string
			for _, host := range httpsHosts[:testsslLimit] {
				binary := "testssl"
				if isToolAvailable("testssl.sh") {
					binary = "testssl.sh"
				}

				output, err := exec.RunCommand(ctx, binary,
					[]string{"--quiet", "--color", "0", host}, nil)

				if err == nil && len(output) > 0 {
					allResults = append(allResults, fmt.Sprintf("=== %s ===", host))
					allResults = append(allResults, string(output))
				}
			}

			outFile = exec.OutputPath("testssl", "results.txt")
			if len(allResults) > 0 {
				writeLines(outFile, allResults)
			}

			green.Printf("  [✓] testssl: %d hosts analyzed (%v)\n", testsslLimit, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "testssl", Success: true, OutputDir: outFile, Lines: len(allResults), Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] SSL/TLS analysis completed (%v)\n", time.Since(start).Round(time.Second))
}
