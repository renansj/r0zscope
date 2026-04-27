package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the global recon configuration.
type Config struct {
	Target            string        `yaml:"target"`
	OutputDir         string        `yaml:"output_dir"`
	Concurrency       int           `yaml:"concurrency"`
	ToolTimeout       time.Duration `yaml:"tool_timeout"`
	Resolvers         []string      `yaml:"resolvers"`
	SubdomainWordlist string        `yaml:"subdomain_wordlist"`
	EnabledModules    []string      `yaml:"enabled_modules"`
	DisabledModules   []string      `yaml:"disabled_modules"`
	RateLimit         int           `yaml:"rate_limit"`
	Proxy             string        `yaml:"proxy"`
	Threads           int           `yaml:"threads"`
	Verbose           bool          `yaml:"verbose"`
	NucleiTemplatesPath string      `yaml:"nuclei_templates_path"`
	NucleiSeverity    string        `yaml:"nuclei_severity"`
	CrawlDepth        int           `yaml:"crawl_depth"`
	InScope           bool          `yaml:"in_scope"`
	CTFMode           bool          `yaml:"ctf_mode"`
	VhostWordlist     string        `yaml:"vhost_wordlist"`
}

// DefaultConfig returns an optimized default configuration.
func DefaultConfig(target string) *Config {
	cores := runtime.NumCPU()
	threads := cores * 2
	if threads < 10 {
		threads = 10
	}
	if threads > 50 {
		threads = 50
	}

	return &Config{
		Target:         target,
		OutputDir:      filepath.Join("recon-output", target),
		Concurrency:    cores * 4,
		ToolTimeout:    30 * time.Minute,
		Resolvers:      []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"},
		Threads:        threads,
		Verbose:        false,
		NucleiSeverity: "critical,high,medium",
		CrawlDepth:     3,
		InScope:        true,
		RateLimit:      0,
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// SaveExample generates an example configuration file.
func SaveExample(path string) error {
	cfg := DefaultConfig("example.com")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := []byte("# Recon Tool Configuration\n# Edit as needed\n\n")
	return os.WriteFile(path, append(header, data...), 0644)
}

// IsModuleEnabled checks whether a module is enabled.
func (c *Config) IsModuleEnabled(name string) bool {
	for _, d := range c.DisabledModules {
		if d == name {
			return false
		}
	}

	if len(c.EnabledModules) == 0 {
		return true
	}

	for _, e := range c.EnabledModules {
		if e == name {
			return true
		}
	}

	return false
}
