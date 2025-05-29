package nuclei

import (
	// Standard
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	// Utils
	report "github.com/Method-Security/webscan/utils/nuclei/report"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	useragent "github.com/projectdiscovery/useragent"
)

type Config struct {
	Targets        []string
	RawRequests    []string // JSONL lines when fuzzing
	FS             []fs.FS  // template sources
	Threads        int
	Proxy          string
	RunMode        nuclei.NucleiRunMode
	SuccessfulOnly *bool
	VerboseLogs    bool
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

func copyTemplatesToTmpDir(cfg Config) (string, error) {
	tmpDir, err := os.MkdirTemp("", "webscan-tpl-*")
	if err != nil {
		return "", err
	}
	for idx, src := range cfg.FS {
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
			dst := filepath.Join(tmpDir, fmt.Sprintf("%02d-%s", idx, filepath.Base(p)))
			return os.WriteFile(dst, data, 0o600)
		})
	}
	return tmpDir, nil
}

func buildNucleiOptions(cfg Config, tmpDir string) []nucleilib.NucleiSDKOptions {
	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{Templates: []string{tmpDir}}),
		nucleilib.EnableSelfContainedTemplates(),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			HeadlessHostConcurrency:       cfg.Threads,
			HostConcurrency:               cfg.Threads,
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads,
			HeadlessTemplateConcurrency:   cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
		}),

		// Explicitly set StopAtFirstMatch to false to ensure we get all requests
		func(e *nucleilib.NucleiEngine) error {
			e.Options().StopAtFirstMatch = false
			return nil
		},
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

func Run(ctx context.Context, cfg Config, reportBuilder *report.Builder) (*nuclei.NucleiReport, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating config")
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	log.Info("SuccessfulOnly config value", svc1log.SafeParam("successfulOnly", cfg.SuccessfulOnly))

	log.Info("Copying templates to tmp dir")
	tmpDir, err := copyTemplatesToTmpDir(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	log.Info("Building Nuclei options")
	opts := buildNucleiOptions(cfg, tmpDir)

	log.Info("Creating Nuclei engine")
	eng, err := nucleilib.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	// To-Do: Write Customer Writer to enable this to work
	if cfg.SuccessfulOnly != nil && *cfg.SuccessfulOnly {
		eng.Options().MatcherStatus = false
	} else {
		eng.Options().MatcherStatus = true
	}
	log.Info("Set matcher status", svc1log.SafeParam("status", eng.Options().MatcherStatus), svc1log.SafeParam("successfulOnly", cfg.SuccessfulOnly))

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
