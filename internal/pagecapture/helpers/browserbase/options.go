package browserbase

import (
	"context"

	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type Option interface {
	applyBrowserbaseOption(*Options)
}

type Options struct {
	Proxy     bool
	Countries []string
}

func NewBrowserbaseOptions(ctx context.Context, opts ...Option) *Options {
	log := svc1log.FromContext(ctx)
	options := &Options{}
	for _, opt := range opts {
		log.Debug("Applying option", svc1log.SafeParam("option", opt))
		opt.applyBrowserbaseOption(options)
	}
	return options
}

type ProxyOption struct {
	Proxy bool
}

func (p ProxyOption) applyBrowserbaseOption(options *Options) {
	options.Proxy = p.Proxy
}

func WithProxy() Option {
	return ProxyOption{Proxy: true}
}

type ProxyCountryOption struct {
	Countries []string
}

func (p ProxyCountryOption) applyBrowserbaseOption(options *Options) {
	options.Proxy = true
	options.Countries = p.Countries
}

func WithProxyCountries(countries []string) Option {
	return ProxyCountryOption{Countries: countries}
}
