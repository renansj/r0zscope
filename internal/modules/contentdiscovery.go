package modules

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/runner"
)

// ContentDiscovery performs directory brute-force and content discovery.
func ContentDiscovery(ctx context.Context, cfg *config.Config, exec *runner.Executor) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n[PHASE 5.5] Content & Directory Discovery")
	cyan.Println(strings.Repeat("─", 60))

	start := time.Now()
	aliveFile := exec.OutputPath("_merged", "all-alive.txt")

	if !runner.FileExists(aliveFile) {
		yellow.Println("  [~] No alive hosts found. Skipping.")
		return
	}

	hasFfuf := isToolAvailable("ffuf")
	hasFerox := isToolAvailable("feroxbuster")
	hasDirsearch := isToolAvailable("dirsearch")
	hasGobuster := isToolAvailable("gobuster")

	if !hasFfuf && !hasFerox && !hasDirsearch && !hasGobuster {
		yellow.Println("  [~] No content discovery tools available (ffuf, feroxbuster, dirsearch, gobuster).")
		return
	}

	wordlists := []string{
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
	}

	wordlist := ""
	for _, wl := range wordlists {
		if _, err := os.Stat(wl); err == nil {
			wordlist = wl
			break
		}
	}

	if wordlist == "" {
		yellow.Println("  [~] No wordlist found. Install seclists: apt install -y seclists")
		return
	}

	fmt.Printf("  [*] Wordlist: %s\n", wordlist)

	aliveURLs := readLines(aliveFile)
	limit := 10
	if len(aliveURLs) < limit {
		limit = len(aliveURLs)
	}

	var wg sync.WaitGroup

	if hasFfuf {
		for i, url := range aliveURLs[:limit] {
			cleanURL := strings.Fields(url)[0]
			if !strings.HasPrefix(cleanURL, "http") {
				cleanURL = "https://" + cleanURL
			}

			wg.Add(1)
			go func(idx int, target string) {
				defer wg.Done()
				modStart := time.Now()

				safeName := strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(target)
				outFile := exec.OutputPath("ffuf", fmt.Sprintf("%s.txt", safeName))

				args := []string{
					"-u", target + "/FUZZ",
					"-w", wordlist,
					"-o", outFile,
					"-of", "csv",
					"-mc", "200,201,202,204,301,302,307,401,403,405",
					"-t", fmt.Sprintf("%d", cfg.Threads/2),
					"-timeout", "10",
					"-s",
				}

				if cfg.RateLimit > 0 {
					args = append(args, "-rate", fmt.Sprintf("%d", cfg.RateLimit))
				}

				_, err := exec.RunCommand(ctx, "ffuf", args, nil)
				lines := runner.CountLines(outFile)

				if err == nil && lines > 0 {
					green.Printf("  [✓] ffuf [%s]: %d paths (%v)\n", target, lines, time.Since(modStart).Round(time.Second))
				}
			}(i, cleanURL)
		}
	} else if hasFerox {
		for i, url := range aliveURLs[:limit] {
			cleanURL := strings.Fields(url)[0]
			if !strings.HasPrefix(cleanURL, "http") {
				cleanURL = "https://" + cleanURL
			}

			wg.Add(1)
			go func(idx int, target string) {
				defer wg.Done()
				modStart := time.Now()

				safeName := strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(target)
				outFile := exec.OutputPath("feroxbuster", fmt.Sprintf("%s.txt", safeName))

				args := []string{
					"-u", target,
					"-w", wordlist,
					"-o", outFile,
					"-t", fmt.Sprintf("%d", cfg.Threads/2),
					"--timeout", "10",
					"-s", "200,201,202,204,301,302,307,401,403",
					"-q",
					"--no-recursion",
				}

				_, err := exec.RunCommand(ctx, "feroxbuster", args, nil)
				lines := runner.CountLines(outFile)

				if err == nil && lines > 0 {
					green.Printf("  [✓] feroxbuster [%s]: %d paths (%v)\n", target, lines, time.Since(modStart).Round(time.Second))
				}
			}(i, cleanURL)
		}
	} else if hasGobuster {
		for i, url := range aliveURLs[:limit] {
			cleanURL := strings.Fields(url)[0]
			if !strings.HasPrefix(cleanURL, "http") {
				cleanURL = "https://" + cleanURL
			}

			wg.Add(1)
			go func(idx int, target string) {
				defer wg.Done()
				modStart := time.Now()

				safeName := strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(target)
				outFile := exec.OutputPath("gobuster", fmt.Sprintf("%s.txt", safeName))

				args := []string{
					"dir",
					"-u", target,
					"-w", wordlist,
					"-o", outFile,
					"-t", fmt.Sprintf("%d", cfg.Threads/2),
					"--timeout", "10s",
					"-s", "200,201,202,204,301,302,307,401,403",
					"-q",
					"--no-error",
				}

				_, err := exec.RunCommand(ctx, "gobuster", args, nil)
				lines := runner.CountLines(outFile)

				if err == nil && lines > 0 {
					green.Printf("  [✓] gobuster [%s]: %d paths (%v)\n", target, lines, time.Since(modStart).Round(time.Second))
				}
			}(i, cleanURL)
		}
	}

	wg.Wait()

	if isToolAvailable("arjun") && runner.FileExists(aliveFile) {
		fmt.Println("  [*] arjun - hidden parameter discovery...")
		arjunLimit := 5
		if len(aliveURLs) < arjunLimit {
			arjunLimit = len(aliveURLs)
		}

		for _, url := range aliveURLs[:arjunLimit] {
			cleanURL := strings.Fields(url)[0]
			if !strings.HasPrefix(cleanURL, "http") {
				cleanURL = "https://" + cleanURL
			}

			safeName := strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(cleanURL)
			outFile := exec.OutputPath("arjun", fmt.Sprintf("%s.json", safeName))

			args := []string{
				"-u", cleanURL,
				"-oJ", outFile,
				"-t", fmt.Sprintf("%d", cfg.Threads/2),
				"--stable",
			}

			exec.RunCommand(ctx, "arjun", args, nil)
			lines := runner.CountLines(outFile)
			if lines > 0 {
				green.Printf("  [✓] arjun [%s]: parameters found\n", cleanURL)
			}
		}

		exec.AddResult(runner.ModuleResult{Module: "arjun", Success: true, OutputDir: exec.ModuleDir("arjun"), Duration: time.Since(start)})
	}

	cyan.Printf("  [TOTAL] Content discovery completed (%v)\n", time.Since(start).Round(time.Second))
}
