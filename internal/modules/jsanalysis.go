package modules

import (
	"bufio"
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

	cyan.Println("\n[PHASE 6] JavaScript Analysis (local files)")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	jsURLsFile := exec.OutputPath("_merged", "js-files.txt")
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")
	katanaStoreDir := exec.OutputPath("katana", "js-responses")
	jsDownloadDir := exec.OutputPath("_jsdownload", "files")

	hasLinkfinder := isToolAvailable("linkfinder")
	hasSecretfinder := isToolAvailable("SecretFinder")
	hasTrufflehog := isToolAvailable("trufflehog")
	hasSemgrep := isToolAvailable("semgrep")
	hasSubjs := isToolAvailable("subjs")

	if !hasLinkfinder && !hasSecretfinder && !hasTrufflehog && !hasSemgrep && !hasSubjs {
		yellow.Println("  [~] No JS analysis tools available.")
		return
	}

	var wg sync.WaitGroup

	// Collect more JS URLs via subjs
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

	// Step 1: Collect JS from katana store-response
	localJSFiles := collectKatanaJSFiles(katanaStoreDir)
	if len(localJSFiles) > 0 {
		fmt.Printf("  [*] %d JS files found in katana store-response\n", len(localJSFiles))
	}

	// Step 2: Always download JS from discovered URLs (most reliable method)
	if runner.FileExists(jsURLsFile) {
		jsURLs := readLines(jsURLsFile)
		if len(jsURLs) > 0 {
			fmt.Printf("  [*] Downloading %d JS files from discovered URLs...\n", len(jsURLs))
			exec.EnsureDir(jsDownloadDir)
			downloaded := downloadJSFiles(ctx, exec, jsURLsFile, jsDownloadDir)
			localJSFiles = append(localJSFiles, downloaded...)
			if len(downloaded) > 0 {
				green.Printf("  [✓] %d JS files downloaded to %s\n", len(downloaded), jsDownloadDir)
			}
		}
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

	// Prefer download dir for directory-level scanners (trufflehog, semgrep)
	jsScanDir := ""
	if info, err := os.Stat(jsDownloadDir); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(jsDownloadDir)
		if len(entries) > 0 {
			jsScanDir = jsDownloadDir
		}
	}
	if jsScanDir == "" {
		if info, err := os.Stat(katanaStoreDir); err == nil && info.IsDir() {
			jsScanDir = katanaStoreDir
		}
	}

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

	if hasTrufflehog && jsScanDir != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] trufflehog - scanning JS directory: %s\n", jsScanDir)

			outFile := exec.OutputPath("trufflehog", "secrets.txt")
			output, err := exec.RunCommand(ctx, "trufflehog", []string{
				"filesystem", jsScanDir, "--no-update", "--json",
			}, nil)

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

	if hasSemgrep && jsScanDir != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			modStart := time.Now()
			fmt.Printf("  [*] semgrep - scanning JS directory for vulnerabilities...\n")

			outFile := exec.OutputPath("semgrep", "findings.txt")
			outJSON := exec.OutputPath("semgrep", "findings.json")

			args := []string{
				"scan",
				"--config", "auto",
				"--lang", "js",
				"--json",
				"--output", outJSON,
				"--quiet",
				jsScanDir,
			}

			exec.RunCommand(ctx, "semgrep", args, nil)

			// Also run with text output for readability
			textArgs := []string{
				"scan",
				"--config", "auto",
				"--lang", "js",
				"--output", outFile,
				"--quiet",
				jsScanDir,
			}
			exec.RunCommand(ctx, "semgrep", textArgs, nil)

			lines := runner.CountLines(outFile)
			if lines > 0 {
				red.Printf("  [!!!] semgrep: %d findings in JS files! (%v)\n", lines, time.Since(modStart).Round(time.Second))
			} else {
				green.Printf("  [✓] semgrep: no findings (%v)\n", time.Since(modStart).Round(time.Second))
			}
			exec.AddResult(runner.ModuleResult{Module: "semgrep", Success: true, OutputDir: outFile, Lines: lines, Duration: time.Since(modStart)})
		}()
	}

	wg.Wait()
	cyan.Printf("  [TOTAL] JS analysis completed (%v)\n", time.Since(start).Round(time.Second))
}

// collectKatanaJSFiles parses katana's store-response directory structure.
// Katana stores responses as: <store-dir>/<domain>/<hash>.txt with an index.txt mapping URLs to files.
// We find JS responses by checking the index for .js URLs, or by scanning response bodies.
func collectKatanaJSFiles(storeDir string) []string {
	var jsFiles []string

	if _, err := os.Stat(storeDir); os.IsNotExist(err) {
		return jsFiles
	}

	seen := make(map[string]struct{})

	// Walk all subdirectories looking for index.txt files
	filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Katana index file maps URLs to response files
		if info.Name() == "index.txt" {
			f, ferr := os.Open(path)
			if ferr != nil {
				return nil
			}
			defer f.Close()

			dir := filepath.Dir(path)
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				// Format: <url> <response-file>
				parts := strings.SplitN(line, " ", 2)
				if len(parts) != 2 {
					continue
				}
				url := strings.ToLower(parts[0])
				respFile := parts[1]

				// Check if URL is a JS file
				cleanURL := url
				if idx := strings.Index(cleanURL, "?"); idx != -1 {
					cleanURL = cleanURL[:idx]
				}

				isJS := strings.HasSuffix(cleanURL, ".js") ||
					strings.HasSuffix(cleanURL, ".mjs") ||
					strings.HasSuffix(cleanURL, ".jsx")

				if isJS {
					fullPath := filepath.Join(dir, respFile)
					if _, exists := seen[fullPath]; !exists {
						if _, serr := os.Stat(fullPath); serr == nil {
							seen[fullPath] = struct{}{}
							jsFiles = append(jsFiles, fullPath)
						}
					}
				}
			}
			return nil
		}

		// Also check files directly by extension or content
		lower := strings.ToLower(info.Name())
		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") {
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				jsFiles = append(jsFiles, path)
			}
			return nil
		}

		// For files without .js extension, check content (katana uses hashes as filenames)
		if info.Size() > 10 && info.Size() < 10*1024*1024 && !strings.HasSuffix(lower, ".txt") {
			if looksLikeJS(path) {
				if _, exists := seen[path]; !exists {
					seen[path] = struct{}{}
					jsFiles = append(jsFiles, path)
				}
			}
		}

		return nil
	})

	return jsFiles
}

func looksLikeJS(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}

	content := string(buf[:n])
	trimmed := strings.TrimSpace(content)

	// Skip HTML responses
	if strings.HasPrefix(trimmed, "<!") || strings.HasPrefix(trimmed, "<html") || strings.HasPrefix(trimmed, "<HTML") {
		return false
	}
	// Skip HTTP headers
	if strings.HasPrefix(trimmed, "HTTP/") {
		return false
	}

	jsSignals := 0
	indicators := []string{
		"function", "var ", "let ", "const ", "(function", "!function",
		"\"use strict\"", "'use strict'", "module.exports", "export ",
		"import ", "require(", "addEventListener", "document.", "window.",
		"prototype", "=>", "async ", "await ", "Promise", "fetch(",
		"XMLHttpRequest", "$.ajax", "axios",
	}

	for _, ind := range indicators {
		if strings.Contains(content, ind) {
			jsSignals++
		}
	}

	return jsSignals >= 2
}

func downloadJSFiles(ctx context.Context, exec *runner.Executor, urlsFile, outputDir string) []string {
	urls := readLines(urlsFile)
	var downloaded []string
	var mu sync.Mutex

	limit := 100
	if len(urls) < limit {
		limit = len(urls)
	}

	sem := make(chan struct{}, 15)
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
