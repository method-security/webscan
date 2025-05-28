package nuclei

import (
	// Standard
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	// Generated
	pentestgeneralfern "github.com/Method-Security/webscan/generated/go/pentest/general"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// All is the pentest templates
//
//go:embed pentest
var All embed.FS

// resourceTypeToFileMap maps the application resource type to the file name of the template.
var resourceTypeToFileMap = map[pentestgeneralfern.ApplicationResourceType]string{
	pentestgeneralfern.ApplicationResourceTypeContentManagementSystem: "cms",
	pentestgeneralfern.ApplicationResourceTypeWebServer:               "webserver",
}

// subFS walks “pentest/<kind>/<subs…>” and returns each matching fs.FS or an error.
func subFS(kind string, subs []string) ([]fs.FS, error) {
	var out []fs.FS
	for _, sub := range subs {
		path := filepath.Join("pentest", kind, sub)
		sub, err := fs.Sub(All, path)
		if err != nil {
			return nil, fmt.Errorf("no templates under %q: %w", path, err)
		}
		out = append(out, sub)
	}
	return out, nil
}

// ScanCategoryFS returns the FS views for the given scanCategory.
// If scanCategory=="technologies", it delegates to ScanFS(resource, modules).
// Otherwise it looks in pentest/scan/<scanCategory>.
func ScanCategoryFS(ctx context.Context, scanCategories []pentestgeneralfern.ScanCategory, resourceTypes []pentestgeneralfern.ApplicationResourceType, modules []string) ([]fs.FS, error) {

	var out []fs.FS
	for _, scanCategory := range scanCategories {
		switch scanCategory {
		case pentestgeneralfern.ScanCategoryTechnologies:
			techFS, err := ScanFS(ctx, resourceTypes, modules)
			if err != nil {
				return nil, err
			}
			out = append(out, techFS...)
		default:
			base := filepath.Join("pentest", "scan", strings.ToLower(string(scanCategory)))
			sub, err := fs.Sub(All, base)
			if err != nil {
				// if user typo, warn but continue
				return nil, fmt.Errorf("unknown scan-category %q", scanCategory)
			}
			out = append(out, sub)
		}
	}
	return out, nil
}

func ScanFS(ctx context.Context, resourceTypes []pentestgeneralfern.ApplicationResourceType, modules []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	// Build the “scan/<resource>/<module>” paths
	var subs []string
	for _, resourceType := range resourceTypes {
		resourceTypeFileName := resourceTypeToFileMap[resourceType]
		if len(modules) == 0 {
			subs = append(subs, resourceTypeFileName)
		} else {
			for _, m := range modules {
				m = strings.ToLower(strings.TrimSpace(m))
				if m == "" {
					continue
				}
				log.Info("Adding template", svc1log.SafeParam("resource", resourceTypeFileName), svc1log.SafeParam("module", m))
				subs = append(subs, filepath.Join(resourceTypeFileName, m))
			}
		}
	}

	return subFS("scan/technologies", subs)
}

func DastFS(dastCategories []pentestgeneralfern.DastCategory) ([]fs.FS, error) {
	// Build the “dast/<vuln>” paths
	var subs []string
	for _, dastCategory := range dastCategories {
		subs = append(subs, strings.ToLower(string(dastCategory)))
	}

	return subFS("dast", subs)
}
