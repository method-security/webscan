package discoverpage

import (
	// Standard
	"bytes"
	"fmt"
	"image/png"

	// External
	goimagehash "github.com/corona10/goimagehash"
)

// ComputeScreenshotPerceptualHash decodes PNG bytes and returns a perceptual hash string
// in the form "p:<hex>" (the default goimagehash format, compatible with gowitness).
func ComputeScreenshotPerceptualHash(pngBytes []byte) (string, error) {
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return "", fmt.Errorf("failed to decode PNG for phash: %w", err)
	}

	hash, err := goimagehash.PerceptionHash(img)
	if err != nil {
		return "", fmt.Errorf("failed to compute perceptual hash: %w", err)
	}

	return hash.ToString(), nil
}
