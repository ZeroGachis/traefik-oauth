package oauth

import (
	"context"
	"net/http"
)

type Config struct{}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next http.Handler
	name string
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Plugin{
		next: next,
		name: name,
	}, nil
}

func (a *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.next.ServeHTTP(rw, req)
}
