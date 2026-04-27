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

// SubdomainTakeover checks for subdomain takeover with multiple tools.
func SubdomainTakeover(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 7] Subdomain Takeover Check")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()

	hasSubjack := isToolAvailable("subjack")
	hasSubzy := isToolAvailable("subzy")

	if !hasSubjack && !hasSubzy {
		yellow.Println("  [~] No takeover tools available (subjack, subzy). Skipping.")
		return
	}

	inputFile := exec.OutputPath("_merged", "all-subdomains.txt")
	if !runner.FileExists(inputFile) {
		yellow.Println("  [~] No subdomains found. Skipping.")
		return
	}

	var wg sync.WaitGroup
	totalTakeovers := 0

	if hasSubzy {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] subzy - checking takeover...")

			outFile := exec.OutputPath("subzy", "takeover.txt")
			args := []string{
				"run",
				"--targets", inputFile,
				"--output", outFile,
				"--concurrency", fmt.Sprintf("%d", cfg.Threads),
				"--hide_fails",
			}

			_, err := exec.RunCommand(ctx, "subzy", args, nil)
			lines := runner.CountLines(outFile)

			if lines > 0 {
				totalTakeovers += lines
				color.New(color.FgRed, color.Bold).Printf("  [!!!] subzy: %d possible takeovers!\n", lines)
			} else {
				green.Printf("  [✓] subzy: no takeover found (%v)\n", time.Since(modStart).Round(time.Second))
			}

			exec.AddResult(runner.ModuleResult{Module: "subzy", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if hasSubjack {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] subjack - checking takeover...")

			outFile := exec.OutputPath("subjack", "takeover.txt")
			args := []string{
				"-w", inputFile,
				"-o", outFile,
				"-ssl",
				"-t", fmt.Sprintf("%d", cfg.Threads),
				"-timeout", "30",
				"-a",
			}

			_, err := exec.RunCommand(ctx, "subjack", args, nil)
			lines := runner.CountLines(outFile)

			if lines > 0 {
				totalTakeovers += lines
				color.New(color.FgRed, color.Bold).Printf("  [!!!] subjack: %d possible takeovers!\n", lines)
			} else {
				green.Printf("  [✓] subjack: no takeover found (%v)\n", time.Since(modStart).Round(time.Second))
			}

			exec.AddResult(runner.ModuleResult{Module: "subjack", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] Takeover check completed (%v)\n", time.Since(start).Round(time.Second))
}
