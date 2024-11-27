package helper

import (
	"net/url"
)

func ExtractURLPath(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "/"
	}
	if parsedURL.Path == "" {
		return "/"
	}
	return parsedURL.Path
}
