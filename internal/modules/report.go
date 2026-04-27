package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
	"github.com/renansj/r0zscope/internal/runner"
)

// GenerateReport generates the final recon report.
func GenerateReport(cfg *config.Config, exec *runner.Executor, totalStart time.Time) {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	bold := color.New(color.Bold)

	cyan.Println("\n╔══════════════════════════════════════════════════════════════╗")
	cyan.Println("║                      FINAL REPORT                          ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════╝")

	results := exec.GetResults()

	fmt.Println()
	bold.Printf("  Target: %s\n", cfg.Target)
	bold.Printf("  Total duration: %v\n", time.Since(totalStart).Round(time.Second))
	bold.Printf("  Output: %s\n", cfg.OutputDir)
	fmt.Println()

	bold.Println("  Results by module:")
	fmt.Println(strings.Repeat("  ─", 30))

	totalFindings := 0
	for _, r := range results {
		status := ""
		if r.Success {
			status = green.Sprintf("✓")
		} else {
			status = red.Sprintf("✗")
		}

		errMsg := ""
		if r.Error != nil {
			errMsg = yellow.Sprintf(" (%v)", r.Error)
		}

		fmt.Printf("  %s %-20s %6d results  %8v%s\n",
			status, r.Module, r.Lines, r.Duration.Round(time.Second), errMsg)

		totalFindings += r.Lines
	}

	fmt.Println(strings.Repeat("  ─", 30))
	bold.Printf("  Total: %d results across %d modules\n", totalFindings, len(results))

	fmt.Println()
	bold.Println("  Consolidated files:")

	mergedDir := filepath.Join(cfg.OutputDir, "_merged")
	mergedFiles := []struct {
		name string
		desc string
	}{
		{"all-subdomains.txt", "Unique subdomains"},
		{"all-alive.txt", "Alive hosts (HTTP/HTTPS)"},
		{"all-urls.txt", "Discovered URLs"},
		{"all-urls-dedup.txt", "Deduplicated URLs (uro)"},
		{"urls-with-params.txt", "URLs with parameters"},
		{"js-files.txt", "JavaScript files"},
	}

	for _, mf := range mergedFiles {
		path := filepath.Join(mergedDir, mf.name)
		lines := runner.CountLines(path)
		if lines > 0 {
			fmt.Printf("  ├─ %-30s %6d  %s\n", mf.name, lines, mf.desc)
		}
	}

	fmt.Println()
	bold.Println("  ⚠ Security alerts:")

	vulnFiles := []struct {
		path string
		desc string
	}{
		{filepath.Join(cfg.OutputDir, "nuclei", "findings.txt"), "Nuclei - general vulnerabilities"},
		{filepath.Join(cfg.OutputDir, "nuclei", "fuzz-findings.txt"), "Nuclei - parameter fuzzing"},
		{filepath.Join(cfg.OutputDir, "dalfox", "xss-findings.txt"), "Dalfox - XSS"},
		{filepath.Join(cfg.OutputDir, "sqlmap", "findings.txt"), "SQLMap - SQL injection"},
		{filepath.Join(cfg.OutputDir, "crlfuzz", "findings.txt"), "CRLFuzz - CRLF injection"},
		{filepath.Join(cfg.OutputDir, "corsy", "findings.json"), "Corsy - CORS misconfiguration"},
		{filepath.Join(cfg.OutputDir, "commix", "findings.txt"), "Commix - command injection"},
		{filepath.Join(cfg.OutputDir, "subjack", "takeover.txt"), "Subjack - subdomain takeover"},
		{filepath.Join(cfg.OutputDir, "subzy", "takeover.txt"), "Subzy - subdomain takeover"},
		{filepath.Join(cfg.OutputDir, "secretfinder", "secrets.txt"), "SecretFinder - JS secrets"},
		{filepath.Join(cfg.OutputDir, "trufflehog", "secrets.txt"), "Trufflehog - credentials"},
		{filepath.Join(cfg.OutputDir, "semgrep", "findings.txt"), "Semgrep - JS static analysis"},
	}

	hasVulns := false
	for _, vf := range vulnFiles {
		lines := runner.CountLines(vf.path)
		if lines > 0 {
			hasVulns = true
			red.Printf("  🔴 %s: %d findings\n", vf.desc, lines)
			fmt.Printf("     └─ %s\n", vf.path)
		}
	}

	if !hasVulns {
		green.Println("  ✅ No critical vulnerabilities found in automated scans.")
	}

	gfDir := filepath.Join(cfg.OutputDir, "gf")
	if _, err := os.Stat(gfDir); err == nil {
		fmt.Println()
		bold.Println("  Potentially vulnerable URLs (gf patterns):")
		entries, _ := os.ReadDir(gfDir)
		for _, entry := range entries {
			if !entry.IsDir() {
				path := filepath.Join(gfDir, entry.Name())
				lines := runner.CountLines(path)
				if lines > 0 {
					pattern := strings.TrimSuffix(entry.Name(), ".txt")
					yellow.Printf("  ├─ %-15s %6d URLs\n", pattern, lines)
				}
			}
		}
	}

	reportPath := filepath.Join(cfg.OutputDir, "REPORT.txt")
	saveReportToFile(reportPath, cfg, results, totalStart)
	fmt.Printf("\n  📄 Report saved to: %s\n", reportPath)

	fmt.Println()
}

func saveReportToFile(path string, cfg *config.Config, results []runner.ModuleResult, totalStart time.Time) {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	var sb strings.Builder

	sb.WriteString(strings.Repeat("=", 70) + "\n")
	sb.WriteString("  WEB RECONNAISSANCE REPORT\n")
	sb.WriteString(strings.Repeat("=", 70) + "\n\n")

	sb.WriteString(fmt.Sprintf("Target:         %s\n", cfg.Target))
	sb.WriteString(fmt.Sprintf("Date:           %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Total duration: %v\n", time.Since(totalStart).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Output dir:     %s\n", cfg.OutputDir))
	sb.WriteString(fmt.Sprintf("Threads:        %d\n", cfg.Threads))
	sb.WriteString(fmt.Sprintf("Resolvers:      %s\n", strings.Join(cfg.Resolvers, ", ")))
	if cfg.Proxy != "" {
		sb.WriteString(fmt.Sprintf("Proxy:          %s\n", cfg.Proxy))
	}
	sb.WriteString("\n")

	sb.WriteString(strings.Repeat("-", 70) + "\n")
	sb.WriteString("RESULTS BY MODULE\n")
	sb.WriteString(strings.Repeat("-", 70) + "\n\n")

	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "FAILED"
		}

		sb.WriteString(fmt.Sprintf("[%-6s] %-20s %6d results  %8v\n",
			status, r.Module, r.Lines, r.Duration.Round(time.Second)))

		if r.Error != nil {
			sb.WriteString(fmt.Sprintf("         Error: %v\n", r.Error))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	sb.WriteString("OUTPUT STRUCTURE\n")
	sb.WriteString(strings.Repeat("-", 70) + "\n\n")

	filepath.Walk(cfg.OutputDir, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(cfg.OutputDir, fpath)
		if rel == "." {
			return nil
		}

		indent := strings.Count(rel, string(os.PathSeparator))
		prefix := strings.Repeat("  ", indent)

		if info.IsDir() {
			sb.WriteString(fmt.Sprintf("%s[DIR] %s/\n", prefix, info.Name()))
		} else {
			lines := runner.CountLines(fpath)
			size := info.Size()
			sizeStr := formatSize(size)
			sb.WriteString(fmt.Sprintf("%s%-35s %6d lines  %8s\n", prefix, info.Name(), lines, sizeStr))
		}
		return nil
	})

	os.WriteFile(path, []byte(sb.String()), 0644)
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}
