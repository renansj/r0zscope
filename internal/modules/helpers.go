package modules

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	return writer.Flush()
}

func openFileAsReader(path string) io.Reader {
	f, err := os.Open(path)
	if err != nil {
		return strings.NewReader("")
	}
	return f
}

func filterParamURLs(inputPath, outputPath string) {
	lines := readLines(inputPath)
	var filtered []string
	seen := make(map[string]struct{})

	for _, line := range lines {
		url := strings.Fields(line)[0]
		if strings.Contains(url, "?") && strings.Contains(url, "=") {
			if _, exists := seen[url]; !exists {
				seen[url] = struct{}{}
				filtered = append(filtered, url)
			}
		}
	}

	writeLines(outputPath, filtered)
}

func filterJSFiles(inputPath, outputPath string) {
	lines := readLines(inputPath)
	var filtered []string
	seen := make(map[string]struct{})

	jsExtensions := []string{".js", ".mjs", ".jsx", ".ts", ".tsx"}

	for _, line := range lines {
		url := strings.Fields(line)[0]
		lower := strings.ToLower(url)

		cleanURL := lower
		if idx := strings.Index(cleanURL, "?"); idx != -1 {
			cleanURL = cleanURL[:idx]
		}

		for _, ext := range jsExtensions {
			if strings.HasSuffix(cleanURL, ext) {
				if _, exists := seen[url]; !exists {
					seen[url] = struct{}{}
					filtered = append(filtered, url)
				}
				break
			}
		}
	}

	writeLines(outputPath, filtered)
}

func consolidateGoSpiderOutput(dir, outputPath string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}

	seen := make(map[string]struct{})
	var allURLs []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		lines := readLines(path)

		for _, line := range lines {
			parts := strings.SplitN(line, " - ", 2)
			url := line
			if len(parts) == 2 {
				url = strings.TrimSpace(parts[1])
			}

			if strings.HasPrefix(url, "http") {
				if _, exists := seen[url]; !exists {
					seen[url] = struct{}{}
					allURLs = append(allURLs, url)
				}
			}
		}
	}

	writeLines(outputPath, allURLs)
	return len(allURLs)
}
