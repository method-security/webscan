//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/Method-Security/webscan/internal/embeddedassets"
)

func main() {
	bundles := []embeddedassets.Bundle{
		{
			Output: "configs/embedded/configs.tar.gz",
			Roots:  []string{"configs/discover", "configs/enumerate", "configs/pentest"},
			Base:   "configs",
		},
		{
			Output: "utils/nuclei/templates/embedded/templates.tar.gz",
			Roots:  []string{"utils/nuclei/templates/discover", "utils/nuclei/templates/pentest"},
			Base:   "utils/nuclei/templates",
		},
	}

	for _, b := range bundles {
		if err := embeddedassets.WriteBundle(b); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", b.Output, err)
			os.Exit(1)
		}
	}
}
