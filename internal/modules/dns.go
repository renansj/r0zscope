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

// DNSResolution performs mass DNS resolution and advanced enumeration.
func DNSResolution(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 2] DNS Resolution & Enumeration")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	inputFile := exec.OutputPath("_merged", "all-subdomains.txt")

	if !runner.FileExists(inputFile) {
		yellow.Println("  [~] No subdomains found in previous phase. Skipping.")
		return
	}

	var wg sync.WaitGroup

	if isToolAvailable("dnsx") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] dnsx - mass DNS resolution...")

			outFile := exec.OutputPath("dnsx", "resolved.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] dnsx: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "dnsx", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{
				"-l", inputFile,
				"-o", outFile,
				"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
				"-resp",
				"-silent",
				"-t", fmt.Sprintf("%d", cfg.Threads),
			}
			if len(cfg.Resolvers) > 0 {
				args = append(args, "-r", strings.Join(cfg.Resolvers, ","))
			}

			_, err := exec.RunCommand(ctx, "dnsx", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] dnsx failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "dnsx", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] dnsx: %d hosts resolved (%v)\n", lines, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "dnsx", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})

			resolvedOnly := exec.OutputPath("dnsx", "resolved-hosts.txt")
			extractResolvedHosts(outFile, resolvedOnly)
		}()
	}

	if isToolAvailable("dnsrecon") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] dnsrecon - zone transfer & advanced enumeration...")

			outFile := exec.OutputPath("dnsrecon", "results.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] dnsrecon: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "dnsrecon", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{
				"-d", cfg.Target,
				"-t", "std,axfr",
			}

			output, err := exec.RunCommand(ctx, "dnsrecon", args, nil)
			if len(output) > 0 {
				writeLines(outFile, []string{string(output)})
			}

			lines := runner.CountLines(outFile)
			if err != nil && lines == 0 {
				yellow.Printf("  [~] dnsrecon failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "dnsrecon", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] dnsrecon: completed (%v)\n", time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "dnsrecon", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()

	cyan.Printf("  [TOTAL] DNS completed (%v)\n", time.Since(start).Round(time.Second))
}

func extractResolvedHosts(inputPath, outputPath string) {
	lines := readLines(inputPath)
	seen := make(map[string]struct{})
	var hosts []string

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			host := strings.TrimSpace(parts[0])
			if host != "" {
				if _, exists := seen[host]; !exists {
					seen[host] = struct{}{}
					hosts = append(hosts, host)
				}
			}
		}
	}

	writeLines(outputPath, hosts)
}
