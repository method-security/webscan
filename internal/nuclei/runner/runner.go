package nuclei

import (
	// Standard
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	// Generated
	nucleifern "github.com/Method-Security/webscan/generated/go/nuclei"
	// Internal
	report "github.com/Method-Security/webscan/internal/nuclei/report"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
)

type Config struct {
	Targets        []string
	RawRequests    []string // JSONL lines when fuzzing
	FS             []fs.FS  // template sources
	Threads        int
	Proxy          string
	RunMode        nucleifern.RunMode
	SuccessfulOnly *bool
}

func validateConfig(cfg Config) error {
	if cfg.RunMode == nucleifern.RunModeDast {
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

func buildNucleiOptions(cfg Config, tmpDir string) []nuclei.NucleiSDKOptions {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{tmpDir}}),
		nuclei.EnableSelfContainedTemplates(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithConcurrency(nuclei.Concurrency{
			HeadlessHostConcurrency:       cfg.Threads,
			HostConcurrency:               cfg.Threads,
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads,
			HeadlessTemplateConcurrency:   cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
	}

	if cfg.RunMode == nucleifern.RunModeDast {
		opts = append(opts, nuclei.DASTMode())
	}

	// proxy
	if cfg.Proxy != "" {
		opts = append(opts, nuclei.WithProxy([]string{cfg.Proxy}, false))
	}

	return opts
}

func loadTargets(eng *nuclei.NucleiEngine, cfg Config) error {
	if cfg.RunMode == nucleifern.RunModeDast {
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

func Run(ctx context.Context, cfg Config, reportBuilder *report.Builder) (*nucleifern.Report, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating config")
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

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
	eng, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	log.Info("Setting matcher status")
	if cfg.SuccessfulOnly != nil && *cfg.SuccessfulOnly {
		eng.Options().MatcherStatus = true
	}

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
