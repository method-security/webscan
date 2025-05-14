package browserbase

import (
	"context"
)

type Option interface {
	applyBrowserbaseOption(*Options)
}

type Options struct {
	Proxy     bool
	Countries []string
}

func NewBrowserbaseOptions(ctx context.Context, proxy bool, countries []string) *Options {
	options := &Options{
		Proxy:     proxy,
		Countries: countries,
	}
	return options
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
