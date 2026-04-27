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

// ModuleResult stores the execution result of a module.
type ModuleResult struct {
	Module    string
	Success   bool
	OutputDir string
	Lines     int
	Duration  time.Duration
	Error     error
}

// Executor manages the execution of external tools.
type Executor struct {
	cfg     *config.Config
	results []ModuleResult
	mu      sync.Mutex
	startAt time.Time
}

// NewExecutor creates a new executor.
func NewExecutor(cfg *config.Config) *Executor {
	return &Executor{
		cfg:     cfg,
		startAt: time.Now(),
	}
}

// RunCommand executes an external command with timeout and output capture.
func (e *Executor) RunCommand(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.ToolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}

	if e.cfg.Verbose {
		color.New(color.FgHiBlack).Printf("    $ %s %s\n", name, strings.Join(args, " "))
	}

	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("timeout after %v", e.cfg.ToolTimeout)
	}

	return output, err
}

// RunCommandToFile executes a command and saves output to a file.
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

	if e.cfg.Verbose {
		color.New(color.FgHiBlack).Printf("    $ %s %s > %s\n", name, strings.Join(args, " "), outputFile)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("failed to create pipe: %w", err)
	}

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
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

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return lineCount, fmt.Errorf("timeout after %v", e.cfg.ToolTimeout)
		}
		if lineCount > 0 {
			return lineCount, nil
		}
		return lineCount, fmt.Errorf("%s failed: %w (stderr: %s)", name, err, stderrBuf.String())
	}

	return lineCount, nil
}

// RunPipeline executes a command pipeline (cmd1 | cmd2 > output).
func (e *Executor) RunPipeline(ctx context.Context, inputFile string, commands [][]string, outputFile string) (int, error) {
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	ctx, cancel := context.WithTimeout(ctx, e.cfg.ToolTimeout)
	defer cancel()

	var input io.Reader
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			return 0, fmt.Errorf("failed to open input %s: %w", inputFile, err)
		}
		defer f.Close()
		input = f
	}

	var lastOutput io.Reader = input
	var cmds []*exec.Cmd

	for i, cmdArgs := range commands {
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		if i == 0 && lastOutput != nil {
			cmd.Stdin = lastOutput
		} else if i > 0 {
			cmd.Stdin = lastOutput
		}

		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return 0, fmt.Errorf("failed to create pipe for %s: %w", cmdArgs[0], err)
		}
		lastOutput = pipe
		cmds = append(cmds, cmd)
	}

	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			for _, c := range cmds {
				if c.Process != nil {
					c.Process.Kill()
				}
			}
			return 0, fmt.Errorf("failed to start pipeline: %w", err)
		}
	}

	f, err := os.Create(outputFile)
	if err != nil {
		for _, c := range cmds {
			if c.Process != nil {
				c.Process.Kill()
			}
		}
		return 0, fmt.Errorf("failed to create output %s: %w", outputFile, err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	scanner := bufio.NewScanner(lastOutput)
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

	for _, cmd := range cmds {
		cmd.Wait()
	}

	return lineCount, nil
}

// EnsureDir ensures a directory exists.
func (e *Executor) EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// OutputPath returns the output path for a module.
func (e *Executor) OutputPath(module, filename string) string {
	return filepath.Join(e.cfg.OutputDir, module, filename)
}

// ModuleDir returns the output directory for a module.
func (e *Executor) ModuleDir(module string) string {
	return filepath.Join(e.cfg.OutputDir, module)
}

// AddResult records a module result.
func (e *Executor) AddResult(result ModuleResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = append(e.results, result)
}

// GetResults returns all results.
func (e *Executor) GetResults() []ModuleResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ModuleResult{}, e.results...)
}

// CountLines counts non-empty lines in a file.
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

// MergeFiles combines multiple files into one, removing duplicates.
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

// FileExists checks whether a file exists and has content.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() > 0
}
