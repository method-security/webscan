package nuclei

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	// Generated
	pentestgeneralfern "github.com/Method-Security/webscan/generated/go/pentest/general"
	// Internal
	report "github.com/Method-Security/webscan/utils/nuclei/report"
	runner "github.com/Method-Security/webscan/utils/nuclei/runner"
	templates "github.com/Method-Security/webscan/utils/nuclei/templates"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const fuzzMarker = "0x6D6574686F64" // Used to mark where to inject fuzzing payloads.

// proxifyRequest is the shape that LoadTargetsWithHttpData("jsonl") expects.
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header   map[string]string `json:"header"`
		Body     string            `json:"body"`
		Raw      string            `json:"raw"`
		Endpoint string            `json:"endpoint"`
	} `json:"request"`
}

// RunScan for scan mode—unchanged.
func RunScan(ctx context.Context, config pentestgeneralfern.Config) (*pentestgeneralfern.Report, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Nuclei Run of mode: Scan")

	var src []fs.FS
	var err error
	if len(config.Scan.Categories) > 0 {
		src, err = templates.ScanCategoryFS(ctx, config.Scan.Categories, config.Scan.ApplicationResourceTypes, config.Scan.Modules)
	} else {
		src, err = templates.ScanFS(ctx, config.Scan.ApplicationResourceTypes, config.Scan.Modules)
	}
	if err != nil {
		return nil, err
	}
	rconfig := runner.Config{
		Targets:        config.Targets,
		FS:             src,
		Threads:        config.Threads,
		Proxy:          getProxy(config),
		RunMode:        config.RunMode,
		SuccessfulOnly: config.SuccessfulOnly,
	}
	builder := report.NewBuilder()
	log.Info("Populating config")
	if err := builder.PopulateConfig(config); err != nil {
		return nil, err
	}
	return runner.Run(ctx, rconfig, builder)
}

// RunDast builds JSONL entries and invokes runner.Run in dast mode.
func RunDast(ctx context.Context, config pentestgeneralfern.Config) (*pentestgeneralfern.Report, error) {
	srcFS, err := templates.DastFS(config.Dast.Categories)
	if err != nil {
		return nil, err
	}
	jsonl := buildJSONL(config)
	rconfig := runner.Config{
		RawRequests:    jsonl,
		FS:             srcFS,
		Threads:        config.Threads,
		Proxy:          getProxy(config),
		RunMode:        config.RunMode,
		SuccessfulOnly: config.SuccessfulOnly,
	}
	builder := report.NewBuilder()
	if err := builder.PopulateConfig(config); err != nil {
		return nil, err
	}
	return runner.Run(ctx, rconfig, builder)
}

func buildJSONL(config pentestgeneralfern.Config) []string {
	var out []string

	for _, method := range config.Dast.HttpMethods {
		for _, tgt := range config.Targets {
			// 1) URL + query
			uStr := strings.ReplaceAll(tgt, "%s", fuzzMarker)
			u, err := url.Parse(uStr)
			if err != nil {
				continue
			}
			q := u.Query()
			for _, p := range config.Dast.RequestParameters {
				if strings.EqualFold(string(p.Location), "query") && p.Value != nil {
					v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
					q.Add(p.Name, v)
				}
			}
			u.RawQuery = q.Encode()

			// 2) headers & cookies
			hmap := map[string]string{}
			for _, p := range config.Dast.RequestParameters {
				if p.Value == nil {
					continue
				}
				v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
				switch strings.ToLower(string(p.Location)) {
				case "header":
					hmap[p.Name] = v
				case "cookie":
					if prev, ok := hmap["Cookie"]; ok {
						hmap["Cookie"] = prev + "; " + fmt.Sprintf("%s=%s", p.Name, v)
					} else {
						hmap["Cookie"] = fmt.Sprintf("%s=%s", p.Name, v)
					}
				}
			}

			// 3) collect all body params for non-GET/HEAD
			bodyParams := url.Values{}
			if !strings.EqualFold(string(method), "GET") &&
				!strings.EqualFold(string(method), "HEAD") {
				for _, p := range config.Dast.RequestParameters {
					if strings.EqualFold(string(p.Location), "body") && p.Value != nil {
						v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
						bodyParams.Add(p.Name, v)
					}
				}
			}
			body := bodyParams.Encode()

			// 4) build raw HTTP string
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n",
				method, u.RequestURI()))
			sb.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))

			if body != "" {
				// include content headers
				sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
				sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
			}
			for k, v := range hmap {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
			sb.WriteString("\r\n")
			if body != "" {
				sb.WriteString(body)
			}
			raw := sb.String()

			// 5) marshal into proxifyRequest JSON
			var pr proxifyRequest
			pr.URL = u.String()
			pr.Request.Header = hmap
			pr.Request.Body = body
			pr.Request.Endpoint = u.RequestURI()
			pr.Request.Raw = raw

			j, err := json.Marshal(pr)
			if err != nil {
				continue
			}
			out = append(out, string(j))
		}
	}
	return out
}
func getProxy(config pentestgeneralfern.Config) string {
	if config.Proxy != nil {
		return *config.Proxy
	}
	return ""
}
