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

// JSAnalysis analyzes JavaScript files downloaded locally by katana.
func JSAnalysis(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	cyan.Println("\n[PHASE 6] JavaScript Analysis (local files)")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	jsURLsFile := exec.OutputPath("_merged", "js-files.txt")
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")
	katanaJSDir := exec.OutputPath("katana", "js-responses")

	hasLinkfinder := isToolAvailable("linkfinder")
	hasSecretfinder := isToolAvailable("SecretFinder")
	hasTrufflehog := isToolAvailable("trufflehog")
	hasSubjs := isToolAvailable("subjs")

	if !hasLinkfinder && !hasSecretfinder && !hasTrufflehog && !hasSubjs {
		yellow.Println("  [~] No JS analysis tools available.")
		return
	}

	var wg sync.WaitGroup

	if hasSubjs && runner.FileExists(aliveFile) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Println("  [*] subjs - extracting JS URLs from hosts...")

			outFile := exec.OutputPath("subjs", "js-files.txt")
			lines, err := exec.RunCommandToFile(ctx, "subjs", []string{"-i", aliveFile}, outFile, nil)

			if err == nil && lines > 0 {
				green.Printf("  [✓] subjs: %d JS files found (%v)\n", lines, time.Since(modStart).Round(time.Second))
				if runner.FileExists(jsURLsFile) {
					runner.MergeFiles(jsURLsFile, jsURLsFile, outFile)
				} else {
					runner.MergeFiles(jsURLsFile, outFile)
				}
			}
			exec.AddResult(runner.ModuleResult{Module: "subjs", Success: err == nil, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
		wg.Wait()
	}

	localJSFiles := collectLocalJSFiles(katanaJSDir)
	fmt.Printf("  [*] %d JS files downloaded locally by katana\n", len(localJSFiles))

	if len(localJSFiles) == 0 && runner.FileExists(jsURLsFile) {
		fmt.Println("  [*] No local JS found. Downloading via URLs...")
		downloadDir := exec.OutputPath("_jsdownload", "files")
		exec.EnsureDir(downloadDir)
		localJSFiles = downloadJSFiles(ctx, exec, jsURLsFile, downloadDir)
		fmt.Printf("  [*] %d JS files downloaded\n", len(localJSFiles))
	}

	if len(localJSFiles) == 0 {
		yellow.Println("  [~] No JavaScript files available for analysis. Skipping.")
		return
	}

	limit := 200
	if len(localJSFiles) < limit {
		limit = len(localJSFiles)
	}
	jsToAnalyze := localJSFiles[:limit]

	fmt.Printf("  [*] %d JavaScript files to analyze\n", len(jsToAnalyze))

	if hasLinkfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] linkfinder - extracting endpoints from %d local JS files...\n", len(jsToAnalyze))

			var allEndpoints []string
			seen := make(map[string]struct{})

			for _, jsPath := range jsToAnalyze {
				output, err := exec.RunCommand(ctx, "linkfinder",
					[]string{"-i", jsPath, "-o", "cli"}, nil)

				if err == nil && len(output) > 0 {
					for _, line := range strings.Split(string(output), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							if _, exists := seen[line]; !exists {
								seen[line] = struct{}{}
								allEndpoints = append(allEndpoints, line)
							}
						}
					}
				}
			}

			outFile := exec.OutputPath("linkfinder", "endpoints.txt")
			if len(allEndpoints) > 0 {
				writeLines(outFile, allEndpoints)
				green.Printf("  [✓] linkfinder: %d endpoints extracted (%v)\n", len(allEndpoints), time.Since(modStart).Round(time.Second))
			} else {
				yellow.Printf("  [~] linkfinder: no endpoints found\n")
			}
			exec.AddResult(runner.ModuleResult{Module: "linkfinder", Success: true, OutputDir: outFile, Lines: len(allEndpoints), Duration: time.Since(modStart)})
		}()
	}

	if hasSecretfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] SecretFinder - scanning %d local JS files for secrets...\n", len(jsToAnalyze))

			var allSecrets []string
			seen := make(map[string]struct{})

			for _, jsPath := range jsToAnalyze {
				output, err := exec.RunCommand(ctx, "SecretFinder",
					[]string{"-i", jsPath, "-o", "cli"}, nil)

				if err == nil && len(output) > 0 {
					for _, line := range strings.Split(string(output), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							if _, exists := seen[line]; !exists {
								seen[line] = struct{}{}
								allSecrets = append(allSecrets, line)
							}
						}
					}
				}
			}

			outFile := exec.OutputPath("secretfinder", "secrets.txt")
			if len(allSecrets) > 0 {
				writeLines(outFile, allSecrets)
				red.Printf("  [!!!] SecretFinder: %d possible secrets found! (%v)\n", len(allSecrets), time.Since(modStart).Round(time.Second))
			} else {
				green.Printf("  [✓] SecretFinder: no secrets found\n")
			}
			exec.AddResult(runner.ModuleResult{Module: "secretfinder", Success: true, OutputDir: outFile, Lines: len(allSecrets), Duration: time.Since(modStart)})
		}()
	}

	if hasTrufflehog {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()

			scanDir := katanaJSDir
			downloadDir := exec.OutputPath("_jsdownload", "files")
			if _, err := os.Stat(downloadDir); err == nil {
				scanDir = downloadDir
			}

			if scanDir == "" {
				return
			}

			fmt.Printf("  [*] trufflehog - scanning JS directory: %s\n", scanDir)

			outFile := exec.OutputPath("trufflehog", "secrets.txt")
			args := []string{
				"filesystem",
				scanDir,
				"--no-update",
				"--json",
			}

			output, err := exec.RunCommand(ctx, "trufflehog", args, nil)

			if err == nil && len(output) > 0 {
				writeLines(outFile, []string{string(output)})
				lines := runner.CountLines(outFile)
				if lines > 0 {
					red.Printf("  [!!!] trufflehog: secrets/credentials found! (%v)\n", time.Since(modStart).Round(time.Second))
				}
				exec.AddResult(runner.ModuleResult{Module: "trufflehog", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
			} else {
				green.Printf("  [✓] trufflehog: no secrets found (%v)\n", time.Since(modStart).Round(time.Second))
				exec.AddResult(runner.ModuleResult{Module: "trufflehog", Success: true, OutputDir: outFile, Lines: 0, Duration: time.Since(modStart)})
			}
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] JS analysis completed (%v)\n", time.Since(start).Round(time.Second))
}

func collectLocalJSFiles(baseDir string) []string {
	var jsFiles []string

	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		return jsFiles
	}

	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		lower := strings.ToLower(info.Name())

		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") {
			jsFiles = append(jsFiles, path)
			return nil
		}

		if info.Size() > 0 && info.Size() < 10*1024*1024 {
			f, ferr := os.Open(path)
			if ferr != nil {
				return nil
			}
			defer f.Close()

			buf := make([]byte, 512)
			n, _ := f.Read(buf)
			if n > 0 {
				content := string(buf[:n])
				trimmed := strings.TrimSpace(content)
				if strings.HasPrefix(trimmed, "function") ||
					strings.HasPrefix(trimmed, "var ") ||
					strings.HasPrefix(trimmed, "let ") ||
					strings.HasPrefix(trimmed, "const ") ||
					strings.HasPrefix(trimmed, "(function") ||
					strings.HasPrefix(trimmed, "!function") ||
					strings.HasPrefix(trimmed, "\"use strict\"") ||
					strings.HasPrefix(trimmed, "'use strict'") ||
					strings.Contains(content, "document.") ||
					strings.Contains(content, "window.") ||
					strings.Contains(content, "module.exports") {
					jsFiles = append(jsFiles, path)
				}
			}
		}

		return nil
	})

	return jsFiles
}

func downloadJSFiles(ctx context.Context, exec *runner.Executor, urlsFile, outputDir string) []string {
	urls := readLines(urlsFile)
	var downloaded []string
	var mu sync.Mutex

	limit := 50
	if len(urls) < limit {
		limit = len(urls)
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, rawURL := range urls[:limit] {
		cleanURL := strings.Fields(rawURL)[0]
		if !strings.HasPrefix(cleanURL, "http") {
			continue
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			safeName := strings.NewReplacer(
				"://", "_", "/", "_", "?", "_", "&", "_",
				"=", "_", ":", "_",
			).Replace(url)
			if len(safeName) > 200 {
				safeName = safeName[:200]
			}
			if !strings.HasSuffix(safeName, ".js") {
				safeName += ".js"
			}

			outPath := filepath.Join(outputDir, safeName)

			if isToolAvailable("curl") {
				exec.RunCommand(ctx, "curl", []string{
					"-sL", "--max-time", "10",
					"-o", outPath,
					url,
				}, nil)
			} else if isToolAvailable("wget") {
				exec.RunCommand(ctx, "wget", []string{
					"-q", "--timeout=10",
					"-O", outPath,
					url,
				}, nil)
			}

			if info, err := os.Stat(outPath); err == nil && info.Size() > 0 {
				mu.Lock()
				downloaded = append(downloaded, outPath)
				mu.Unlock()
			}
		}(cleanURL)
	}

	wg.Wait()
	return downloaded
}
