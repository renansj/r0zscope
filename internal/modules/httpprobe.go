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

// HTTPProbe checks which subdomains are alive via HTTP/HTTPS.
func HTTPProbe(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	cyan.Println("\n[PHASE 3] HTTP Probing")
	cyan.Println(strings.Repeat("─", 50))

	start := time.Now()
	inputFile := exec.OutputPath("_merged", "all-subdomains.txt")

	if !runner.FileExists(inputFile) {
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		modStart := time.Now()
		fmt.Println("  [*] httpx (probe + tech detect)...")

		outFile := exec.OutputPath("httpx", "alive.txt")
		if alreadyDone(outFile) {
			green.Printf("  [skip] httpx: output already exists\n")
			cleanFile := exec.OutputPath("httpx", "urls-clean.txt")
			extractCleanURLs(outFile, cleanFile)
			addOutput(cleanFile)
			exec.AddResult(runner.ModuleResult{Module: "httpx", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
			return
		}

		args := []string{
			"-l", inputFile,
			"-o", outFile,
			"-status-code",
			"-content-length",
			"-title",
			"-tech-detect",
			"-web-server",
			"-follow-redirects",
			"-silent",
			"-threads", fmt.Sprintf("%d", cfg.Threads),
			"-timeout", "10",
			"-retries", "2",
		}

		if cfg.RateLimit > 0 {
			args = append(args, "-rate-limit", fmt.Sprintf("%d", cfg.RateLimit))
		}

		_, err := exec.RunCommand(ctx, "httpx", args, nil)
		lines := runner.CountLines(outFile)

		if err != nil && lines == 0 {
			red.Printf("  [✗] httpx failed: %v\n", err)
			exec.AddResult(runner.ModuleResult{Module: "httpx", Success: false, Error: err, Duration: time.Since(modStart)})
			return
		}

		green.Printf("  [✓] httpx: %d alive hosts (%v)\n", lines, time.Since(modStart).Round(time.Second))

		cleanFile := exec.OutputPath("httpx", "urls-clean.txt")
		extractCleanURLs(outFile, cleanFile)

		addOutput(cleanFile)
		exec.AddResult(runner.ModuleResult{Module: "httpx", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
	}()

	if isToolAvailable("httprobe") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] httprobe...")

			outFile := exec.OutputPath("httprobe", "alive.txt")
			if alreadyDone(outFile) {
				green.Printf("  [skip] httprobe: output already exists\n")
				addOutput(outFile)
				exec.AddResult(runner.ModuleResult{Module: "httprobe", Success: true, OutputDir: outFile, Lines: runner.CountLines(outFile), Duration: 0})
				return
			}
			lines, err := exec.RunCommandToFile(ctx, "httprobe",
				[]string{"-c", fmt.Sprintf("%d", cfg.Threads), "-t", "10000"},
				outFile,
				openFileAsReader(inputFile),
			)

			if err != nil && lines == 0 {
				yellow.Printf("  [~] httprobe failed: %v\n", err)
				exec.AddResult(runner.ModuleResult{Module: "httprobe", Success: false, Error: err, Duration: time.Since(modStart)})
				return
			}

			green.Printf("  [✓] httprobe: %d alive hosts (%v)\n", lines, time.Since(modStart).Round(time.Second))
			addOutput(outFile)
			exec.AddResult(runner.ModuleResult{Module: "httprobe", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()

	mergedFile := exec.OutputPath("_merged", "all-alive.txt")
	total, err := runner.MergeFiles(mergedFile, outputs...)
	if err != nil {
		red.Printf("  [✗] Merge error: %v\n", err)
		return
	}

	cyan.Printf("\n  [TOTAL] %d unique alive hosts (%v)\n", total, time.Since(start).Round(time.Second))
	fmt.Printf("  └─ %s\n", mergedFile)
}

func extractCleanURLs(inputPath, outputPath string) {
	lines := readLines(inputPath)
	var clean []string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			url := parts[0]
			if strings.HasPrefix(url, "http") {
				clean = append(clean, url)
			}
		}
	}
	writeLines(outputPath, clean)
}
