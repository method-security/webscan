package fingerprint

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"reflect"
	"strings"

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

func tlsVersionToString(version uint16) webscan.TlsVersion {
	switch version {
	case tls.VersionTLS10:
		return webscan.TlsVersionTls10
	case tls.VersionTLS11:
		return webscan.TlsVersionTls11
	case tls.VersionTLS12:
		return webscan.TlsVersionTls12
	case tls.VersionTLS13:
		return webscan.TlsVersionTls13
	default:
		return webscan.TlsVersionUnknown
	}
}

func convertToTLSInfo(state *tls.ConnectionState) *webscan.TlsInfo {
	tlsInfo := &webscan.TlsInfo{
		Certificates: []*webscan.Certificate{},
	}

	if state.Version != 0 {
		version := tlsVersionToString(state.Version)
		tlsInfo.Version = &version
	}

	if state.CipherSuite != 0 {
		cipherSuite := tls.CipherSuiteName(state.CipherSuite)
		tlsInfo.CipherSuite = &cipherSuite
	}

	for _, cert := range state.PeerCertificates {
		serialNumber := cert.SerialNumber.String()
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		certString := string(certPEM)
		signatureHex := hex.EncodeToString(cert.Signature)
		certificate := &webscan.Certificate{
			SubjectCommonName: &cert.Subject.CommonName,
			IssuerCommonName:  &cert.Issuer.CommonName,
			ValidFrom:         &cert.NotBefore,
			ValidTo:           &cert.NotAfter,
			Version:           &cert.Version,
			SerialNumber:      &serialNumber,
			Certificate:       &certString,
			Signature:         &signatureHex,
		}

		// Signature names defined in `signatureAlgorithmDetails` in the `x509` package have a hyphen
		// Which is removed for proper enum conversion
		signatureAlgorithm, err := webscan.NewSignatureAlgorithmFromString(strings.Replace(cert.SignatureAlgorithm.String(), "-", "", 1))
		if err == nil {
			certificate.SignatureAlgorithm = &signatureAlgorithm
		}
		publicKeyAlgorithm, err := webscan.NewPublicKeyAlgorithmFromString(cert.PublicKeyAlgorithm.String())
		if err == nil {
			certificate.PublicKeyAlgorithm = &publicKeyAlgorithm
		}

		tlsInfo.Certificates = append(tlsInfo.Certificates, certificate)
	}

	return tlsInfo
}
