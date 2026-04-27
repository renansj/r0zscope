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

// PortScan performs port scanning on hosts with naabu and nmap.
func PortScan(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 4] Port Scanning")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()

	inputFile := exec.OutputPath("_merged", "all-subdomains.txt")
	if !runner.FileExists(inputFile) {
		yellow.Println("  [~] No subdomains found. Skipping.")
		return
	}

	hasNaabu := isToolAvailable("naabu")
	hasNmap := isToolAvailable("nmap")

	if !hasNaabu && !hasNmap {
		yellow.Println("  [~] No port scanner available (naabu, nmap). Skipping.")
		return
	}

	var wg sync.WaitGroup

	if hasNaabu {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] naabu - fast port scan (top 1000)...")

			outFile := exec.OutputPath("naabu", "ports.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] naabu: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "naabu", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			args := []string{
				"-list", inputFile,
				"-o", outFile,
				"-top-ports", "1000",
				"-silent",
				"-c", fmt.Sprintf("%d", cfg.Threads),
				"-rate", "1000",
			}

			_, err := exec.RunCommand(ctx, "naabu", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] naabu failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "naabu", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] naabu: %d open ports (%v)\n", lines, time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "naabu", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if hasNmap {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] nmap - service detection (top 100)...")

			outFile := exec.OutputPath("nmap", "services.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] nmap: output already exists\n")
				exec.AddResult(runner.ModuleResult{Module: "nmap", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			xmlFile := exec.OutputPath("nmap", "scan.xml")

			hosts := readLines(inputFile)
			limit := 20
			if len(hosts) < limit {
				limit = len(hosts)
			}
			limitedFile := exec.OutputPath("nmap", "targets.txt")
			writeLines(limitedFile, hosts[:limit])

			args := []string{
				"-iL", limitedFile,
				"-sV",
				"--top-ports", "100",
				"-T4",
				"--open",
				"-oN", outFile,
				"-oX", xmlFile,
				"--min-rate", "300",
			}

			_, err := exec.RunCommand(ctx, "nmap", args, nil)
			lines := runner.CountLines(outFile)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] nmap failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "nmap", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] nmap: service detection completed (%v)\n", time.Since(modStart).Round(time.Second))
			exec.AddResult(runner.ModuleResult{Module: "nmap", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] Port scan completed (%v)\n", time.Since(start).Round(time.Second))
}
