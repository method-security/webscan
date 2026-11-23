# HTTP Client

Existing clients retain their defaults: a 30-second timeout, certificate
verification, TLS 1.2 minimum, HTTP/2 negotiation, up to ten redirects, and fully
buffered response bodies without a size limit.

## Custom Transports

`WithTransport(*http.Transport)` clones a caller-configured transport. This lets a
scanner connect to a specific IP and port while using a separate URL hostname for
HTTP Host and TLS SNI. The clone owns its connections; call
`client.CloseIdleConnections()` when finished. Do not modify the source transport's
configuration concurrently with client construction.

The supplied transport controls dialing, TLS (including verification), HTTP/2,
and connection settings. `WithTLSVerify` only affects the default transport.
Explicit HTTP/SOCKS proxy options still apply to the clone; SOCKS replaces its
custom dialer. Do not enable proxies when direct IP-pinned dialing is required.

```go
transport := &http.Transport{
    DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, network, "192.0.2.10:443")
    },
    DisableKeepAlives: true,
}
client := httpclient.New(
    httpclient.WithTransport(transport),
    httpclient.WithTimeout(5*time.Second),
    httpclient.WithDefaultHeaders(map[string]string{"User-Agent": selectedUserAgent}),
)
defer client.CloseIdleConnections()

response, err := client.Head(ctx, "https://app.example.com/")
```

Callers can supply `transport.TLSClientConfig` for explicit SNI, self-signed
certificates, or discovery-only legacy TLS requirements. These settings are not
enabled globally or by default.

The existing request methods retain their normal timeout, redirect, and response
buffering behavior. Scanner-specific request sequences and service classification
belong in the calling application, not this package.

## Bounded Bodies

`WithMaxResponseBodyBytes(n)` optionally limits buffered bodies returned by the
existing request methods. A positive limit returns at most `n` bytes and
`ErrResponseBodyTooLarge` when exceeded; the returned response retains status and
headers. Use `errors.Is(err, httpclient.ErrResponseBodyTooLarge)` to distinguish
this condition. JSON convenience methods stop on this error rather than decoding
truncated JSON. Zero or negative limits preserve unlimited buffering. `IsAlive`
still evaluates the returned status when the only error is an oversized body;
404 and 502 remain unavailable, and other request errors still return false.
