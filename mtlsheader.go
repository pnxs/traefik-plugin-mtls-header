// Package traefik_plugin_mtls_header a custom header plugin
// nolint
package traefik_plugin_mtls_header

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	Headers   map[string]string `json:"headers,omitempty"`
	EncodeURL bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers:   make(map[string]string),
		EncodeURL: false,
	}
}

// MtlsHeader a MtlsHeader plugin.
type MtlsHeader struct {
	next      http.Handler
	headers   map[string]string
	encodeURL bool
	name      string
	template  *template.Template
}

// New created a new MtlsHeader plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &MtlsHeader{
		headers:   config.Headers,
		encodeURL: config.EncodeURL,
		next:      next,
		name:      name,
		template:  template.New("mtlsheader").Delims("[[", "]]"),
	}, nil
}

type data struct {
	Request *http.Request
	Cert    *x509.Certificate
}

func (a *MtlsHeader) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	data := data{
		Request: req,
		Cert:    nil,
	}

	// load certificate
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		for _, cert := range req.TLS.PeerCertificates {
			data.Cert = cert
			break
		}
	}

	for key, value := range a.headers {
		tmpl, err := a.template.Parse(value)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		writer := &bytes.Buffer{}

		err = tmpl.Execute(writer, data)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if a.encodeURL {
			req.Header.Set(key, url.QueryEscape(writer.String()))
		} else {
			req.Header.Set(key, writer.String())
		}
	}

	a.next.ServeHTTP(rw, req)
}
