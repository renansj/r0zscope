package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/renansj/r0zscope/internal/config"
)

type ModuleResult struct {
	Module    string
	Success   bool
	OutputDir string
	Lines     int
	Duration  time.Duration
	Error     error
}

type Executor struct {
	cfg     *config.Config
	results []ModuleResult
	mu      sync.Mutex
	startAt time.Time
}

func NewExecutor(cfg *config.Config) *Executor {
	return &Executor{
		cfg:     cfg,
		startAt: time.Now(),
	}
}

func (e *Executor) debugPath(toolName string) string {
	return filepath.Join(e.cfg.OutputDir, "_debug", toolName+".log")
}

func (e *Executor) saveDebug(toolName string, cmdLine string, stderr string, err error) {
	if stderr == "" && err == nil {
		return
	}
	dir := filepath.Join(e.cfg.OutputDir, "_debug")
	os.MkdirAll(dir, 0755)

	f, ferr := os.OpenFile(e.debugPath(toolName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if ferr != nil {
		return
	}
	defer f.Close()

	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), cmdLine))
	if err != nil {
		f.WriteString(fmt.Sprintf("EXIT: %v\n", err))
	}
	if stderr != "" {
		f.WriteString(fmt.Sprintf("STDERR:\n%s\n", stderr))
	}
	f.WriteString(strings.Repeat("-", 60) + "\n")
}

func (e *Executor) RunCommand(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.ToolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}

	cmdLine := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	if e.cfg.Verbose {
		color.New(color.FgHiBlack).Printf("    $ %s\n", cmdLine)
	}

	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		e.saveDebug(name, cmdLine, stderrBuf.String(), fmt.Errorf("timeout after %v", e.cfg.ToolTimeout))
		return []byte(stdoutBuf.String()), fmt.Errorf("timeout after %v", e.cfg.ToolTimeout)
	}

	if err != nil {
		e.saveDebug(name, cmdLine, stderrBuf.String(), err)
	}

	combined := stdoutBuf.String() + stderrBuf.String()
	return []byte(combined), err
}

func (e *Executor) RunCommandToFile(ctx context.Context, name string, args []string, outputFile string, stdin io.Reader) (int, error) {
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	ctx, cancel := context.WithTimeout(ctx, e.cfg.ToolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}

	cmdLine := fmt.Sprintf("%s %s > %s", name, strings.Join(args, " "), outputFile)
	if e.cfg.Verbose {
		color.New(color.FgHiBlack).Printf("    $ %s\n", cmdLine)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("failed to create pipe: %w", err)
	}

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		e.saveDebug(name, cmdLine, "", err)
		return 0, fmt.Errorf("failed to start %s: %w", name, err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		cmd.Process.Kill()
		return 0, fmt.Errorf("failed to create file %s: %w", outputFile, err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			writer.WriteString(line + "\n")
			lineCount++
		}
	}
	writer.Flush()

	if werr := cmd.Wait(); werr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			e.saveDebug(name, cmdLine, stderrBuf.String(), fmt.Errorf("timeout after %v", e.cfg.ToolTimeout))
			return lineCount, fmt.Errorf("timeout after %v", e.cfg.ToolTimeout)
		}
		e.saveDebug(name, cmdLine, stderrBuf.String(), werr)
		if lineCount > 0 {
			return lineCount, nil
		}
		return lineCount, fmt.Errorf("%s failed: %w (stderr: %s)", name, werr, stderrBuf.String())
	}

	return lineCount, nil
}

func (e *Executor) EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func (e *Executor) OutputPath(module, filename string) string {
	return filepath.Join(e.cfg.OutputDir, module, filename)
}

func (e *Executor) ModuleDir(module string) string {
	return filepath.Join(e.cfg.OutputDir, module)
}

func (e *Executor) AddResult(result ModuleResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = append(e.results, result)
}

func (e *Executor) GetResults() []ModuleResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ModuleResult{}, e.results...)
}

func CountLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func MergeFiles(outputPath string, inputPaths ...string) (int, error) {
	seen := make(map[string]struct{})
	var lines []string

	for _, path := range inputPaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if _, exists := seen[line]; !exists {
				seen[line] = struct{}{}
				lines = append(lines, line)
			}
		}
		f.Close()
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	writer.Flush()

	return len(lines), nil
}

func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() > 0
}
