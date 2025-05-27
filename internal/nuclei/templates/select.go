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
	nucleifern "github.com/Method-Security/webscan/generated/go/nuclei"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// All is the pentest templates
//
//go:embed pentest
var All embed.FS

var resoure_type_to_file_map = map[nucleifern.ApplicationResourceType]string{
	nucleifern.ApplicationResourceTypeContentManagementSystem: "cms",
	nucleifern.ApplicationResourceTypeWebServer:               "webserver",
}

// subFS walks “pentest/<kind>/<subs…>” and returns each matching fs.FS or an error.
func subFS(kind string, subs []string) ([]fs.FS, error) {
	var out []fs.FS
	for _, s := range subs {
		p := filepath.Join("pentest", kind, s)
		sub, err := fs.Sub(All, p)
		if err != nil {
			return nil, fmt.Errorf("no templates under %q: %w", p, err)
		}
		out = append(out, sub)
	}
	return out, nil
}

// ScanCategoryFS returns the FS views for the given scanCategory.
// If scanCategory=="technologies", it delegates to ScanFS(resource, modules).
// Otherwise it looks in pentest/scan/<scanCategory>.
func ScanCategoryFS(ctx context.Context, scanCategory []nucleifern.ScanCategory, resourceTypes []nucleifern.ApplicationResourceType, modules []string) ([]fs.FS, error) {

	var out []fs.FS
	for _, st := range scanCategory {
		switch st {
		case nucleifern.ScanCategoryTechnologies:
			techFS, err := ScanFS(ctx, resourceTypes, modules)
			if err != nil {
				return nil, err
			}
			out = append(out, techFS...)
		default:
			base := filepath.Join("pentest", "scan", strings.ToLower(string(st)))
			sub, err := fs.Sub(All, base)
			if err != nil {
				// if user typo, warn but continue
				return nil, fmt.Errorf("unknown scan-category %q", st)
			}
			out = append(out, sub)
		}
	}
	return out, nil
}

func ScanFS(ctx context.Context, rTypes []nucleifern.ApplicationResourceType, modules []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)
	// Validate & default
	rTypes, err := wantResource(rTypes)
	if err != nil {
		return nil, err
	}

	// Build the “scan/<resource>/<module>” paths
	var subs []string
	for _, rt := range rTypes {
		rtName := resoure_type_to_file_map[rt]
		if len(modules) == 0 {
			subs = append(subs, rtName)
		} else {
			for _, m := range modules {
				m = strings.ToLower(strings.TrimSpace(m))
				if m == "" {
					continue
				}
				log.Info("Adding template", svc1log.SafeParam("resource", rtName), svc1log.SafeParam("module", m))
				subs = append(subs, filepath.Join(rtName, m))
			}
		}
	}

	return subFS("scan/technologies", subs)
}

func DastFS(dCategories []nucleifern.DastCategory) ([]fs.FS, error) {
	// Validate & default
	dCategories, err := wantDastCategory(dCategories)
	if err != nil {
		return nil, err
	}

	// Build the “dast/<vuln>” paths
	var subs []string
	for _, dc := range dCategories {
		subs = append(subs, strings.ToLower(string(dc)))
	}

	return subFS("dast", subs)
}

// wantResource validates the resource types and returns the valid resource types
func wantResource(in []nucleifern.ApplicationResourceType) ([]nucleifern.ApplicationResourceType, error) {
	all := []nucleifern.ApplicationResourceType{
		nucleifern.ApplicationResourceTypeApiApplication,
		nucleifern.ApplicationResourceTypeContentManagementSystem,
		nucleifern.ApplicationResourceTypeWebServer,
	}
	if len(in) == 0 {
		return all, nil
	}
	for _, rt := range in {
		switch rt {
		case nucleifern.ApplicationResourceTypeApiApplication, nucleifern.ApplicationResourceTypeContentManagementSystem, nucleifern.ApplicationResourceTypeWebServer:
		default:
			return nil, fmt.Errorf("unknown resource type %q", rt)
		}
	}
	return in, nil
}

// wantDastCategory validates the DastCategory types and returns the valid categories
func wantDastCategory(in []nucleifern.DastCategory) ([]nucleifern.DastCategory, error) {
	// exactly match the enum in your Fern spec
	all := []nucleifern.DastCategory{
		nucleifern.DastCategorySqli,
		nucleifern.DastCategoryXss,
		nucleifern.DastCategorySsti,
		nucleifern.DastCategoryCommandInjection,
		nucleifern.DastCategoryPathTraversal,
	}
	if len(in) == 0 {
		return all, nil
	}
	// membership set
	valid := map[nucleifern.DastCategory]struct{}{
		nucleifern.DastCategorySqli:             {},
		nucleifern.DastCategoryXss:              {},
		nucleifern.DastCategorySsti:             {},
		nucleifern.DastCategoryCommandInjection: {},
		nucleifern.DastCategoryPathTraversal:    {},
	}
	for _, vt := range in {
		if _, ok := valid[vt]; !ok {
			return nil, fmt.Errorf("unknown vuln type %q", vt)
		}
	}
	return in, nil
}
