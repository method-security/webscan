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
func ScanCategoryFS(ctx context.Context, scanCategory []pentestgeneralfern.ScanCategory, resourceTypes []pentestgeneralfern.ApplicationResourceType, modules []string) ([]fs.FS, error) {

	var out []fs.FS
	for _, st := range scanCategory {
		switch st {
		case pentestgeneralfern.ScanCategoryTechnologies:
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

func ScanFS(ctx context.Context, rTypes []pentestgeneralfern.ApplicationResourceType, modules []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)
	// Validate & default
	rTypes, err := wantResource(rTypes)
	if err != nil {
		return nil, err
	}

	// Build the “scan/<resource>/<module>” paths
	var subs []string
	for _, rt := range rTypes {
		rtName := resourceTypeToFileMap[rt]
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

func DastFS(dCategories []pentestgeneralfern.DastCategory) ([]fs.FS, error) {
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
func wantResource(in []pentestgeneralfern.ApplicationResourceType) ([]pentestgeneralfern.ApplicationResourceType, error) {
	all := []pentestgeneralfern.ApplicationResourceType{
		pentestgeneralfern.ApplicationResourceTypeApiApplication,
		pentestgeneralfern.ApplicationResourceTypeContentManagementSystem,
		pentestgeneralfern.ApplicationResourceTypeWebServer,
	}
	if len(in) == 0 {
		return all, nil
	}
	for _, rt := range in {
		switch rt {
		case pentestgeneralfern.ApplicationResourceTypeApiApplication, pentestgeneralfern.ApplicationResourceTypeContentManagementSystem, pentestgeneralfern.ApplicationResourceTypeWebServer:
		default:
			return nil, fmt.Errorf("unknown resource type %q", rt)
		}
	}
	return in, nil
}

// wantDastCategory validates the DastCategory types and returns the valid categories
func wantDastCategory(in []pentestgeneralfern.DastCategory) ([]pentestgeneralfern.DastCategory, error) {
	// exactly match the enum in your Fern spec
	all := []pentestgeneralfern.DastCategory{
		pentestgeneralfern.DastCategorySqli,
		pentestgeneralfern.DastCategoryXss,
		pentestgeneralfern.DastCategorySsti,
		pentestgeneralfern.DastCategoryCommandInjection,
		pentestgeneralfern.DastCategoryPathTraversal,
	}
	if len(in) == 0 {
		return all, nil
	}
	// membership set
	valid := map[pentestgeneralfern.DastCategory]struct{}{
		pentestgeneralfern.DastCategorySqli:             {},
		pentestgeneralfern.DastCategoryXss:              {},
		pentestgeneralfern.DastCategorySsti:             {},
		pentestgeneralfern.DastCategoryCommandInjection: {},
		pentestgeneralfern.DastCategoryPathTraversal:    {},
	}
	for _, vt := range in {
		if _, ok := valid[vt]; !ok {
			return nil, fmt.Errorf("unknown vuln type %q", vt)
		}
	}
	return in, nil
}
