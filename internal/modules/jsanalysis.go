package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/runner"
)

func JSAnalysis(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	cyan.Println("\n[PHASE 6] JavaScript Analysis")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	jsURLsFile := exec.OutputPath("_merged", "js-files.txt")
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")
	jsDir := exec.OutputPath("_jsfiles", "downloaded")
	exec.EnsureDir(jsDir)

	hasLinkfinder := isToolAvailable("linkfinder")
	hasSecretfinder := isToolAvailable("SecretFinder")
	hasTrufflehog := isToolAvailable("trufflehog")
	hasSemgrep := isToolAvailable("semgrep")
	hasSubjs := isToolAvailable("subjs")

	if !hasLinkfinder && !hasSecretfinder && !hasTrufflehog && !hasSemgrep && !hasSubjs {
		yellow.Println("  [~] No JS analysis tools available.")
		return
	}

	// Collect more JS URLs via subjs (parallel with other prep)
	if hasSubjs && runner.FileExists(aliveFile) {
		modStart := time.Now()
		fmt.Println("  [*] subjs - extracting JS URLs from hosts...")
		outFile := exec.OutputPath("subjs", "js-files.txt")
		lines, err := exec.RunCommandToFile(ctx, "subjs", []string{"-i", aliveFile}, outFile, nil)
		if err == nil && lines > 0 {
			green.Printf("  [✓] subjs: %d JS URLs found (%v)\n", lines, time.Since(modStart).Round(time.Second))
			if runner.FileExists(jsURLsFile) {
				runner.MergeFiles(jsURLsFile, jsURLsFile, outFile)
			} else {
				runner.MergeFiles(jsURLsFile, outFile)
			}
		}
		exec.AddResult(runner.ModuleResult{Module: "subjs", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
	}

	if !runner.FileExists(jsURLsFile) {
		yellow.Println("  [~] No JavaScript URLs found. Skipping.")
		return
	}

	// Download all JS files in parallel
	jsURLs := readLines(jsURLsFile)
	if len(jsURLs) == 0 {
		yellow.Println("  [~] No JavaScript URLs found. Skipping.")
		return
	}

	fmt.Printf("  [*] Downloading %d JS files...\n", len(jsURLs))
	dlStart := time.Now()
	localFiles := downloadJS(ctx, exec, jsURLs, jsDir, cfg.Threads)
	green.Printf("  [✓] %d JS files downloaded (%v)\n", len(localFiles), time.Since(dlStart).Round(time.Second))

	if len(localFiles) == 0 {
		yellow.Println("  [~] No JS files downloaded. Skipping analysis.")
		return
	}

	fmt.Printf("  [*] Analyzing %d JS files...\n", len(localFiles))

	// Run all analysis tools in parallel
	var wg sync.WaitGroup

	if hasLinkfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] linkfinder - %d files...\n", len(localFiles))

			var results []string
			seen := make(map[string]struct{})
			var mu sync.Mutex

			sem := make(chan struct{}, cfg.Threads)
			var lwg sync.WaitGroup

			for _, f := range localFiles {
				lwg.Add(1)
				go func(path string) {
					defer lwg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					out, err := exec.RunCommand(ctx, "linkfinder", []string{"-i", path, "-o", "cli"}, nil)
					if err != nil || len(out) == 0 {
						return
					}
					mu.Lock()
					for _, line := range strings.Split(string(out), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							if _, exists := seen[line]; !exists {
								seen[line] = struct{}{}
								results = append(results, line)
							}
						}
					}
					mu.Unlock()
				}(f)
			}
			lwg.Wait()

			outFile := exec.OutputPath("linkfinder", "endpoints.txt")
			if len(results) > 0 {
				writeLines(outFile, results)
				green.Printf("  [✓] linkfinder: %d endpoints (%v)\n", len(results), time.Since(modStart).Round(time.Second))
			} else {
				yellow.Printf("  [~] linkfinder: no endpoints found\n")
			}
			exec.AddResult(runner.ModuleResult{Module: "linkfinder", Success: true, OutputDir: outFile, Lines: len(results), Duration: time.Since(modStart)})
		}()
	}

	if hasSecretfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] SecretFinder - %d files...\n", len(localFiles))

			var results []string
			seen := make(map[string]struct{})
			var mu sync.Mutex

			sem := make(chan struct{}, cfg.Threads)
			var swg sync.WaitGroup

			for _, f := range localFiles {
				swg.Add(1)
				go func(path string) {
					defer swg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					out, err := exec.RunCommand(ctx, "SecretFinder", []string{"-i", path, "-o", "cli"}, nil)
					if err != nil || len(out) == 0 {
						return
					}
					mu.Lock()
					for _, line := range strings.Split(string(out), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							if _, exists := seen[line]; !exists {
								seen[line] = struct{}{}
								results = append(results, line)
							}
						}
					}
					mu.Unlock()
				}(f)
			}
			swg.Wait()

			outFile := exec.OutputPath("secretfinder", "secrets.txt")
			if len(results) > 0 {
				writeLines(outFile, results)
				red.Printf("  [!!!] SecretFinder: %d possible secrets! (%v)\n", len(results), time.Since(modStart).Round(time.Second))
			} else {
				green.Printf("  [✓] SecretFinder: clean (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "secretfinder", Success: true, OutputDir: outFile, Lines: len(results), Duration: time.Since(modStart)})
		}()
	}

	if hasTrufflehog {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] trufflehog - filesystem scan...")

			outFile := exec.OutputPath("trufflehog", "secrets.txt")
			out, err := exec.RunCommand(ctx, "trufflehog", []string{"filesystem", jsDir, "--no-update", "--json"}, nil)

			lines := 0
			if err == nil && len(out) > 0 {
				writeLines(outFile, []string{string(out)})
				lines = runner.CountLines(outFile)
			}

			if lines > 0 {
				red.Printf("  [!!!] trufflehog: secrets found! (%v)\n", time.Since(modStart).Round(time.Second))
			} else {
				green.Printf("  [✓] trufflehog: clean (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "trufflehog", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	if hasSemgrep {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] semgrep - static analysis...")

			outJSON := exec.OutputPath("semgrep", "findings.json")
			outFile := exec.OutputPath("semgrep", "findings.txt")

			exec.RunCommand(ctx, "semgrep", []string{
				"scan", "--config", "auto", "--lang", "js",
				"--json", "--output", outJSON, "--quiet", jsDir,
			}, nil)

			exec.RunCommand(ctx, "semgrep", []string{
				"scan", "--config", "auto", "--lang", "js",
				"--output", outFile, "--quiet", jsDir,
			}, nil)

			lines := runner.CountLines(outFile)
			if lines > 0 {
				red.Printf("  [!!!] semgrep: %d findings! (%v)\n", lines, time.Since(modStart).Round(time.Second))
			} else {
				green.Printf("  [✓] semgrep: clean (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "semgrep", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] JS analysis completed (%v)\n", time.Since(start).Round(time.Second))
}

func downloadJS(ctx context.Context, exec *runner.Executor, urls []string, outputDir string, threads int) []string {
	var downloaded []string
	var mu sync.Mutex

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, rawURL := range urls {
		u := strings.Fields(rawURL)[0]
		if !strings.HasPrefix(u, "http") {
			continue
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := strings.NewReplacer("://", "_", "/", "_", "?", "_", "&", "_", "=", "_", ":", "_").Replace(url)
			if len(name) > 180 {
				name = name[:180]
			}
			if !strings.HasSuffix(name, ".js") {
				name += ".js"
			}
			out := filepath.Join(outputDir, name)

			if _, err := os.Stat(out); err == nil {
				mu.Lock()
				downloaded = append(downloaded, out)
				mu.Unlock()
				return
			}

			if isToolAvailable("wget") {
				exec.RunCommand(ctx, "wget", []string{"-q", "--timeout=8", "-O", out, url}, nil)
			} else {
				exec.RunCommand(ctx, "curl", []string{"-sL", "--max-time", "8", "-o", out, url}, nil)
			}

			if info, err := os.Stat(out); err == nil && info.Size() > 0 {
				mu.Lock()
				downloaded = append(downloaded, out)
				mu.Unlock()
			} else {
				os.Remove(out)
			}
		}(u)
	}

	wg.Wait()
	return downloaded
}
