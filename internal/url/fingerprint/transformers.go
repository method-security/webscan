package fingerprint

import (
	"net/http"
	"reflect"

	webscan "github.com/Method-Security/webscan/generated/go/url"
)

// Map of HTTP header names to struct field names
var headerMap = map[string]string{
	"Allow":                        "AllowedHttpMethods",
	"Location":                     "Location",
	"Server":                       "Server",
	"X-Powered-By":                 "XPoweredBy",
	"X-Frame-Options":              "XFrameOptions",
	"X-Cluster-Name":               "XClusterName",
	"Cross-Origin-Resource-Policy": "CrossOriginResourcePolicy",
	"Access-Control-Allow-Origin":  "AccessControlAllowOrigin",
	"X-AspNet-Version":             "XAspNetVersion",
}

func assignHeaders(headers http.Header) *webscan.HttpHeaders {
	httpHeaders := &webscan.HttpHeaders{}
	v := reflect.ValueOf(httpHeaders).Elem()
	for headerName, fieldName := range headerMap {
		if headerValue := headers.Get(headerName); headerValue != "" {
			field := v.FieldByName(fieldName)
			if field.IsValid() && field.CanSet() && field.Kind() == reflect.Ptr {
				field.Set(reflect.ValueOf(&headerValue))
			}
		}
	}

	return httpHeaders
}
