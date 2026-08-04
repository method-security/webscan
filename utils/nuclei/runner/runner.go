package nuclei

import (
	// Standard
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"

	// Utils
	report "github.com/Method-Security/webscan/utils/nuclei/report"
	useragent "github.com/Method-Security/webscan/utils/useragent"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/gologger"
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
)

type Config struct {
	Targets         []string
	RawRequests     []string // JSONL lines when fuzzing
	TemplateFS      []fs.FS  // template sources
	WorkflowFS      []fs.FS  // workflow sources
	Threads         int
	Proxy           string
	RunMode         nuclei.NucleiRunMode
	SuccessfulOnly  *bool
	VerboseLogs     bool
	Timeout         int
	GlobalRateLimit int
	GlobalTimeout   int
	UserAgent       common.UserAgentPreset
}

func validateConfig(cfg *Config) error {
	if cfg.RunMode == nuclei.NucleiRunModeDast {
		if len(cfg.RawRequests) == 0 {
			return fmt.Errorf("runner: no RawRequests provided for dast mode")
		}
	} else {
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("runner: no Targets provided for scan mode")
		}
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}
	return nil
}

func copyFilesToTmpDirs(cfg Config) (templateDir, workflowDir string, err error) {
	// Create template directory
	templateDir, err = os.MkdirTemp("", "webscan-tpl-*")
	if err != nil {
		return "", "", err
	}

	// Create workflow directory
	workflowDir, err = os.MkdirTemp("", "webscan-wf-*")
	if err != nil {
		_ = os.RemoveAll(templateDir)
		return "", "", err
	}

	// Copy templates
	for _, src := range cfg.TemplateFS {
		if walkErr := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return err
			}
			dst := filepath.Join(templateDir, filepath.Base(p))
			return os.WriteFile(dst, data, 0o600)
		}); walkErr != nil {
			return "", "", fmt.Errorf("failed to copy templates: %w", walkErr)
		}
	}

	// Copy workflows with subtemplates structure
	subtemplatesDir := filepath.Join(workflowDir, "subtemplates")
	if err := os.MkdirAll(subtemplatesDir, 0o755); err != nil {
		return "", "", err
	}

	for _, src := range cfg.WorkflowFS {
		if walkErr := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return err
			}

			// Determine if this is a workflow file or a template file
			filename := filepath.Base(p)
			var dst string
			if strings.Contains(string(data), "workflows:") {
				// This is a workflow file - put it in the root
				dst = filepath.Join(workflowDir, filename)
			} else {
				// This is a template file - put it in subtemplates/
				dst = filepath.Join(subtemplatesDir, filename)
			}
			return os.WriteFile(dst, data, 0o600)
		}); walkErr != nil {
			return "", "", fmt.Errorf("failed to copy workflows: %w", walkErr)
		}
	}

	return templateDir, workflowDir, nil
}

func buildNucleiOptions(cfg Config, templateDir, workflowDir string) []nucleilib.NucleiSDKOptions {
	templateSources := nucleilib.TemplateSources{}

	// Only add template directory if it has content
	if len(cfg.TemplateFS) > 0 {
		templateSources.Templates = []string{templateDir}
	}

	// Only add workflow directory if it has content
	if len(cfg.WorkflowFS) > 0 {
		templateSources.Workflows = []string{workflowDir}
	}

	// Create a custom catalog that points to our workflow directory for template resolution
	var customCatalog *disk.DiskCatalog
	if len(cfg.WorkflowFS) > 0 {
		customCatalog = disk.NewCatalog(workflowDir)
	}

	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithLogger(gologger.DefaultLogger),
		nucleilib.WithTemplatesOrWorkflows(templateSources),
		nucleilib.EnableSelfContainedTemplates(),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout: cfg.Timeout,
		}),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			HeadlessHostConcurrency:       cfg.Threads,
			HostConcurrency:               cfg.Threads,
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads,
			HeadlessTemplateConcurrency:   cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
		}),

		// Set global rate limit if specified (0 means use default nuclei rate limit)
		func() nucleilib.NucleiSDKOptions {
			if cfg.GlobalRateLimit > 0 {
				return nucleilib.WithGlobalRateLimit(cfg.GlobalRateLimit, time.Second)
			}
			return func(*nucleilib.NucleiEngine) error { return nil } // no-op, use default
		}(),

		// Explicitly set StopAtFirstMatch to false to ensure we get all requests
		func(e *nucleilib.NucleiEngine) error {
			e.Options().StopAtFirstMatch = false
			// Add timeout configuration
			e.Options().Timeout = cfg.Timeout
			return nil
		},
	}

	// Enable headless browser only for DAST mode (e.g. XSS workflows)
	if cfg.RunMode == nuclei.NucleiRunModeDast {
		opts = append(opts, nucleilib.EnableHeadlessWithOpts(
			&nucleilib.HeadlessOpts{
				PageTimeout: cfg.Timeout,
				ShowBrowser: false,
				UseChrome:   true,
				HeadlessOptions: func() []string {
					baseOptions := []string{
						"--no-sandbox",
						"--disable-dev-shm-usage",
						"--disable-gpu",
						"--mute-audio",
						"--disable-background-timer-throttling",
						"--disable-web-security",
						"--disable-features=VizDisplayCompositor",
						"--timeout=" + fmt.Sprintf("%d000", cfg.Timeout),
					}
					if cfg.Proxy != "" {
						baseOptions = append(baseOptions, "--proxy-server="+cfg.Proxy)
					}
					return baseOptions
				}(),
			},
		))
	}

	// Add custom catalog if we have workflows
	if customCatalog != nil {
		opts = append(opts, nucleilib.WithCatalog(customCatalog))
	}

	// Add verbose logs if enabled
	if cfg.VerboseLogs {
		opts = append(opts, nucleilib.WithVerbosity(nucleilib.VerbosityOptions{Silent: false, Debug: true, Verbose: true}))
	}

	// Resolve the User-Agent from the configured preset. An empty/RANDOM preset
	// resolves to a random browser UA, preserving prior default behavior.
	resolvedUserAgent := useragent.Resolve(cfg.UserAgent)
	opts = append(opts, nucleilib.WithHeaders([]string{fmt.Sprintf("User-Agent:%s", resolvedUserAgent)}))

	if cfg.RunMode == nuclei.NucleiRunModeDast {
		opts = append(opts, nucleilib.DASTMode())
	}

	// proxy
	if cfg.Proxy != "" {
		opts = append(opts, nucleilib.WithProxy([]string{cfg.Proxy}, false))
	}

	return opts
}

func loadTargets(eng *nucleilib.NucleiEngine, cfg Config) error {
	if cfg.RunMode == nuclei.NucleiRunModeDast {
		// write JSONL to temp file
		f, err := os.CreateTemp("", "requests-*.jsonl")
		if err != nil {
			return err
		}
		tmpName := f.Name()
		defer func() {
			_ = os.Remove(tmpName)
		}()
		for _, line := range cfg.RawRequests {
			if _, err := f.WriteString(line + "\n"); err != nil {
				_ = f.Close()
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}

		// tell Nuclei to parse JSONL
		if err := eng.LoadTargetsWithHttpData(tmpName, "jsonl"); err != nil {
			return err
		}
	} else {
		// scan mode: by URL
		eng.LoadTargets(cfg.Targets, false)
	}
	return nil
}

// getProxy returns the proxy URL from the config, or an empty string if no proxy is set.
func getProxy(config nuclei.NucleiConfig) string {
	if config.Proxy != nil {
		return *config.Proxy
	}
	return ""
}

// GetRunnerConfig returns a runner config from a nuclei config.
func GetRunnerConfig(templateFileSystems, workflowFileSystems []fs.FS, config nuclei.NucleiConfig) Config {
	rconfig := Config{
		Targets:         config.Targets,
		TemplateFS:      templateFileSystems,
		WorkflowFS:      workflowFileSystems,
		Threads:         config.Threads,
		Proxy:           getProxy(config),
		RunMode:         config.RunMode,
		VerboseLogs:     config.VerboseLogs,
		Timeout:         config.Timeout,
		GlobalRateLimit: config.GlobalRateLimit,
		GlobalTimeout:   config.GlobalTimeout,
		UserAgent:       config.UserAgent,
	}
	return rconfig
}

func Run(ctx context.Context, cfg Config, reportBuilder *report.Builder) ([]*nuclei.NucleiTargetInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating config")
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	// Add a maximum execution timeout for the entire scan to prevent hanging
	var scanCtx context.Context
	var cancel context.CancelFunc
	if cfg.GlobalTimeout > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.GlobalTimeout)*time.Second)
	} else {
		scanCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	log.Info("Scan global timeout", svc1log.SafeParam("globalTimeout", cfg.GlobalTimeout))

	log.Info("Copying templates and workflows to tmp dirs")
	templateDir, workflowDir, err := copyFilesToTmpDirs(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(templateDir)
		_ = os.RemoveAll(workflowDir)
	}()

	log.Info("Building Nuclei options")
	opts := buildNucleiOptions(cfg, templateDir, workflowDir)

	log.Info("Creating Nuclei engine")
	eng, err := nucleilib.NewNucleiEngineCtx(scanCtx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	eng.Options().MatcherStatus = false
	log.Info("Set matcher status", svc1log.SafeParam("status", eng.Options().MatcherStatus))

	log.Info("Loading targets")
	if err := loadTargets(eng, cfg); err != nil {
		return nil, err
	}

	log.Info("Populating probes")
	if err := reportBuilder.PopulateProbes(eng); err != nil {
		return nil, err
	}

	log.Info("Executing Nuclei engine")
	if err := eng.ExecuteCallbackWithCtx(scanCtx, reportBuilder.Consume); err != nil {
		return nil, err
	}

	log.Info("Returning report")
	return reportBuilder.Final(), nil
}
