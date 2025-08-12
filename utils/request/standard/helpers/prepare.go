package standard

import (
	// Standard
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ConstructURL(ctx context.Context, request *common.HttpRequest) (*string, error) {
	log := svc1log.FromContext(ctx)
	parsedURL, err := url.Parse(request.BaseUrl)
	if err != nil {
		log.Error("Failed to parse base URL", svc1log.SafeParam("error", err))
		return nil, err
	}

	// Path
	standardizedPath := strings.TrimRight(request.Path, "/")
	if request.Params.Path != nil {
		for k, v := range request.Params.Path {
			standardizedPath = strings.ReplaceAll(standardizedPath, fmt.Sprintf("{%s}", k), url.PathEscape(v))
		}
	}
	parsedURL.Path = standardizedPath

	// Query
	q := parsedURL.Query()
	if request.Params.Query != nil {
		for k, v := range request.Params.Query {
			q.Add(k, v)
		}
	}
	parsedURL.RawQuery = q.Encode()

	urlStr := parsedURL.String()
	return &urlStr, nil
}

func PrepareRequestBody(ctx context.Context, request *common.HttpRequest) (io.Reader, error) {
	log := svc1log.FromContext(ctx)
	if request.Params == nil || request.Params.Body == nil {
		return nil, nil
	}

	body := request.Params.Body
	var contentType *string

	switch body.GetKind() {
	case "json":
		// Use the JSON string directly
		jsonData := []byte(body.Json.Data)

		if body.Json.MimeType != nil {
			contentType = body.Json.MimeType
		} else {
			contentTypeStr := "application/json"
			contentType = &contentTypeStr
		}

		// Initialize the headers map if it doesn't exist
		if request.Params.Headers == nil {
			request.Params.Headers = make(map[string][]string)
		}

		// If the Content-Type header is not already set, set it
		if _, exists := request.Params.Headers["Content-Type"]; !exists {
			request.Params.Headers["Content-Type"] = []string{*contentType}
		}

		return bytes.NewReader(jsonData), nil

	case "form":
		// Initialize the values map
		values := url.Values{}
		for k, v := range body.Form.Fields {
			values.Set(k, v)
		}
		if body.Form.MimeType != nil {
			contentType = body.Form.MimeType
		} else {
			contentTypeStr := "application/x-www-form-urlencoded"
			contentType = &contentTypeStr
		}

		// Initialize the headers map if it doesn't exist
		if request.Params.Headers == nil {
			request.Params.Headers = make(map[string][]string)
		}

		// If the Content-Type header is not already set, set it
		if _, exists := request.Params.Headers["Content-Type"]; !exists {
			request.Params.Headers["Content-Type"] = []string{*contentType}
		}
		return strings.NewReader(values.Encode()), nil

	case "multipart":
		buf := &bytes.Buffer{}
		writer := multipart.NewWriter(buf)
		for _, part := range body.Multipart.Parts {
			// Convert headers to MIMEHeader
			mimeHeader := make(textproto.MIMEHeader)
			for k, v := range part.Headers {
				mimeHeader.Set(k, v)
			}

			// Create a new part
			partWriter, err := writer.CreatePart(mimeHeader)
			if err != nil {
				return nil, fmt.Errorf("failed to create multipart part: %v", err)
			}

			// Decode base64 content
			content, err := base64.StdEncoding.DecodeString(part.Content.Base64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 content: %v", err)
			}

			// Write the content
			if _, err := partWriter.Write(content); err != nil {
				return nil, fmt.Errorf("failed to write multipart content: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("failed to close multipart writer: %v", err)
		}
		if body.Multipart.MimeType != nil {
			contentType = body.Multipart.MimeType
		} else {
			contentTypeStr := writer.FormDataContentType()
			contentType = &contentTypeStr
		}

		// Initialize the headers map if it doesn't exist
		if request.Params.Headers == nil {
			request.Params.Headers = make(map[string][]string)
		}

		// If the Content-Type header is not already set, set it
		if _, exists := request.Params.Headers["Content-Type"]; !exists {
			request.Params.Headers["Content-Type"] = []string{*contentType}
		}

		return buf, nil

	case "text":
		if body.Text.Encoding != nil {
			// Handle different encodings if needed
			// For now, we'll just use the text as is
			log.Warn("Text encoding not yet implemented", svc1log.SafeParam("encoding", *body.Text.Encoding))
		}
		if body.Text.MimeType != nil {
			contentType = body.Text.MimeType
		} else {
			contentTypeStr := "text/plain"
			contentType = &contentTypeStr
		}

		// Initialize the headers map if it doesn't exist
		if request.Params.Headers == nil {
			request.Params.Headers = make(map[string][]string)
		}

		// If the Content-Type header is not already set, set it
		if _, exists := request.Params.Headers["Content-Type"]; !exists {
			request.Params.Headers["Content-Type"] = []string{*contentType}
		}

		return strings.NewReader(body.Text.Value), nil

	case "binary":
		content, err := base64.StdEncoding.DecodeString(body.Binary.Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %v", err)
		}
		if body.Binary.MimeType != nil {
			contentType = body.Binary.MimeType
		} else {
			contentTypeStr := "application/octet-stream"
			contentType = &contentTypeStr
		}
		if request.Params.Headers == nil {
			request.Params.Headers = make(map[string][]string)
		}

		// If the Content-Type header is not already set, set it
		if _, exists := request.Params.Headers["Content-Type"]; !exists {
			request.Params.Headers["Content-Type"] = []string{*contentType}
		}

		return bytes.NewReader(content), nil

	default:
		return nil, fmt.Errorf("unknown body type: %s", body.Kind)
	}
}
