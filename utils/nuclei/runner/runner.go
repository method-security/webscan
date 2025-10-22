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
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	// Utils
	report "github.com/Method-Security/webscan/utils/nuclei/report"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	useragent "github.com/projectdiscovery/useragent"
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
}

func validateConfig(cfg Config) error {
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
		_ = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
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
		})
	}

	// Copy workflows with subtemplates structure
	subtemplatesDir := filepath.Join(workflowDir, "subtemplates")
	if err := os.MkdirAll(subtemplatesDir, 0o755); err != nil {
		return "", "", err
	}

	for _, src := range cfg.WorkflowFS {
		_ = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
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
		})
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
		nucleilib.WithTemplatesOrWorkflows(templateSources),
		nucleilib.EnableSelfContainedTemplates(),
		nucleilib.DisableUpdateCheck(),
		nucleilib.EnableHeadlessWithOpts(
			&nucleilib.HeadlessOpts{
				PageTimeout: 30,
				ShowBrowser: false,
				UseChrome:   true,
				HeadlessOptions: func() []string {
					baseOptions := []string{
						"--no-sandbox",            // needed when running as root or in many Docker images
						"--disable-dev-shm-usage", // avoids /dev/shm size limits in containers
						"--disable-gpu",           // GPU isn't available in headless Linux anyway
						"--mute-audio",
						"--disable-background-timer-throttling",
					}
					if cfg.Proxy != "" {
						baseOptions = append(baseOptions, "--proxy-server="+cfg.Proxy)
					}
					return baseOptions
				}(),
			},
		),
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
			return nil
		},
	}

	// Add custom catalog if we have workflows
	if customCatalog != nil {
		opts = append(opts, nucleilib.WithCatalog(customCatalog))
	}

	// Add verbose logs if enabled
	if cfg.VerboseLogs {
		opts = append(opts, nucleilib.WithVerbosity(nucleilib.VerbosityOptions{Silent: false, Debug: true, Verbose: true}))
	}

	// Add random user agent
	randomUserAgent := useragent.PickRandom()
	opts = append(opts, nucleilib.WithHeaders([]string{fmt.Sprintf("User-Agent:%s", randomUserAgent.Raw)}))

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
		defer func() {
			_ = os.Remove(f.Name())
		}()
		for _, line := range cfg.RawRequests {
			if _, err := f.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		_ = f.Sync()

		// tell Nuclei to parse JSONL
		if err := eng.LoadTargetsWithHttpData(f.Name(), "jsonl"); err != nil {
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
	}
	return rconfig
}

func Run(ctx context.Context, cfg Config, reportBuilder *report.Builder) ([]*nuclei.NucleiTargetInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating config")
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

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
	eng, err := nucleilib.NewNucleiEngineCtx(ctx, opts...)
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
	if err := eng.ExecuteCallbackWithCtx(ctx, reportBuilder.Consume); err != nil {
		return nil, err
	}

	log.Info("Returning report")
	return reportBuilder.Final(), nil
}
