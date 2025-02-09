package traefik_signature_plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// Config holds the plugin configuration
type Config struct {
	SecretKey string   `json:"secretKey,omitempty"`
	Headers   []string `json:"headers,omitempty"`
}

// CreateConfig initializes the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		SecretKey: "test",
		Headers:   []string{"X-Date", "Authorization", "APP-ID"},
	}
}

// SignatureMiddleware is the struct for the middleware
type SignatureMiddleware struct {
	next      http.Handler
	secretKey string
	headers   []string
}

// New creates a new instance of the middleware
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &SignatureMiddleware{
		next:      next,
		secretKey: config.SecretKey,
		headers:   config.Headers,
	}, nil
}

// ServeHTTP processes the request, generates the signature, and adds it to the headers
func (s *SignatureMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Extract query string
	queryString := req.URL.RawQuery

	// Collect header values
	var data strings.Builder
	data.WriteString(queryString)
	for _, header := range s.headers {
		if value := req.Header.Get(header); value != "" {
			data.WriteString(value)
		}
	}
	data.WriteString(s.secretKey)

	// Generate SHA-256 hash
	hash := sha256.Sum256([]byte(data.String()))
	signature := hex.EncodeToString(hash[:])

	// Add the generated signature to headers
	req.Header.Set("X-Signature", signature)

	// Proceed with the request
	s.next.ServeHTTP(rw, req)
}
