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
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	// Utils
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

// RunNucleiEngine runs the Nuclei engine with the given config.
func RunNucleiEngine(ctx context.Context, config nuclei.NucleiConfig) ([]*nuclei.NucleiTargetInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Nuclei Run of mode: Scan")

	// Get the template file system
	var fileSystems []fs.FS
	var err error
	fileSystems, err = templates.GetTemplateFileSystem(ctx, config.TemplatePaths)
	if err != nil {
		return nil, err
	}

	// Get the runner config
	runnerConfig := runner.GetRunnerConfig(fileSystems, config)

	// Build the raw requests for dast mode
	if config.RunMode == nuclei.NucleiRunModeDast {
		runnerConfig.RawRequests = buildJSONL(config)
	}

	// Build the report builder and run the nuclei engine
	builder := report.NewBuilder()
	return runner.Run(ctx, runnerConfig, builder)
}

func buildJSONL(config nuclei.NucleiConfig) []string {
	var out []string

	for _, method := range config.Dast.HttpMethods {
		for _, target := range config.Targets {
			// 1) URL + query
			urlStr := strings.ReplaceAll(target, "%s", fuzzMarker)
			u, err := url.Parse(urlStr)
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
			headersMap := map[string]string{}
			for _, p := range config.Dast.RequestParameters {
				if p.Value == nil {
					continue
				}
				v := strings.ReplaceAll(*p.Value, "%s", fuzzMarker)
				switch strings.ToLower(string(p.Location)) {
				case "header":
					headersMap[p.Name] = v
				case "cookie":
					if prev, ok := headersMap["Cookie"]; ok {
						headersMap["Cookie"] = prev + "; " + fmt.Sprintf("%s=%s", p.Name, v)
					} else {
						headersMap["Cookie"] = fmt.Sprintf("%s=%s", p.Name, v)
					}
				}
			}

			// 3) collect all body params for non-GET/HEAD
			bodyParams := url.Values{}
			if !strings.EqualFold(string(method), "GET") &&
				!strings.EqualFold(string(method), "HEAD") {
				for _, requestParameter := range config.Dast.RequestParameters {
					if strings.EqualFold(string(requestParameter.Location), "body") && requestParameter.Value != nil {
						v := strings.ReplaceAll(*requestParameter.Value, "%s", fuzzMarker)
						bodyParams.Add(requestParameter.Name, v)
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
			for headerName, headerValue := range headersMap {
				sb.WriteString(fmt.Sprintf("%s: %s\r\n", headerName, headerValue))
			}
			sb.WriteString("\r\n")
			if body != "" {
				sb.WriteString(body)
			}
			raw := sb.String()

			// 5) marshal into proxifyRequest JSON
			var proxifyRequest proxifyRequest
			proxifyRequest.URL = u.String()
			proxifyRequest.Request.Header = headersMap
			proxifyRequest.Request.Body = body
			proxifyRequest.Request.Endpoint = u.RequestURI()
			proxifyRequest.Request.Raw = raw

			j, err := json.Marshal(proxifyRequest)
			if err != nil {
				continue
			}
			out = append(out, string(j))
		}
	}
	return out
}
