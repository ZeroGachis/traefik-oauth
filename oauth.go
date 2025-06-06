package traefik_oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	JwksEndpoints []string
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next             http.Handler
	name             string
	public_keys      map[string]*rsa.PublicKey
	public_keys_lock sync.RWMutex
	cancelCtx        context.Context //nolint: containedctx
	jwksEndpoints    []*url.URL
	httpClient       *http.Client
}

var backgroundRefreshPublicKeysCancel map[string]context.CancelFunc = make(map[string]context.CancelFunc) //nolint:gochecknoglobals,lll

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	plugin := &Plugin{
		next:          next,
		name:          name,
		public_keys:   make(map[string]*rsa.PublicKey),
		jwksEndpoints: []*url.URL{},
		httpClient:    &http.Client{},
	}

	if err := plugin.ParseJwksEndpoints(config.JwksEndpoints); err != nil {
		plugin.logError(err.Error())

		return nil, errors.New("auth failed")
	}

	if backgroundRefreshPublicKeysCancel[name] != nil {
		plugin.logInfo(fmt.Sprint("Cancel BackgroundRefreshPublicKeys: ", name))
		backgroundRefreshPublicKeysCancel[name]()
	}
	cancel, cancelFunc := context.WithCancel(ctx)
	backgroundRefreshPublicKeysCancel[name] = cancelFunc
	plugin.cancelCtx = cancel
	go plugin.BackgroundRefreshPublicKeys()

	return plugin, nil
}

func (plugin *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := plugin.ValidateToken(req, rw); err != nil {
		plugin.logError(err.Error())
		http.Error(rw, "Auth failed", http.StatusUnauthorized)

		return
	}
	plugin.next.ServeHTTP(rw, req)
}

func (plugin *Plugin) ParseJwksEndpoints(jwks_endpoints []string) error {
	for _, jwks_endpoint := range jwks_endpoints {
		url, err := url.ParseRequestURI(jwks_endpoint)
		if err != nil {
			return fmt.Errorf("ParseJwksEndpoints - invalid url: '%s'", jwks_endpoint)
		}

		plugin.jwksEndpoints = append(plugin.jwksEndpoints, url)
	}

	return nil
}

type JwtHeader struct {
	Algorithm string `json:"alg"`
	Kid       string `json:"kid"`
}

func (plugin *Plugin) ValidateToken(request *http.Request, rw http.ResponseWriter) error {
	authorization_header, ok := request.Header["Authorization"]
	if !ok {
		return errors.New("authorization header missing")
	}

	if !strings.HasPrefix(authorization_header[0], "Bearer ") {
		return errors.New("authorization header type is not bearer")
	}
	jwt_token := authorization_header[0][7:]

	parts := strings.Split(jwt_token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("jwt header is not base64 encoded")
	}
	_, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("jwt payload is not base64 encoded")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("jwt signature is not base64 encoded")
	}

	var jwt_header JwtHeader
	err = json.Unmarshal(header, &jwt_header)
	if err != nil {
		return err
	}
	if jwt_header.Algorithm != "RS256" {
		return errors.New("jwt must use RS256 algorithm")
	}

	public_key, ok := plugin.public_keys[jwt_header.Kid]
	if !ok {
		return fmt.Errorf("no signature for kid=%s", jwt_header.Kid)
	}
	jwt_token_header_and_payload := jwt_token[0 : len(parts[0])+len(parts[1])+1]
	err = VerifySignature(public_key, []byte(jwt_token_header_and_payload), signature)
	if err != nil {
		return fmt.Errorf("invalid signature %w", err)
	}

	return nil
}

func VerifySignature(public_key *rsa.PublicKey, value []byte, signature []byte) error {
	hash := crypto.SHA256.New()
	_, err := hash.Write(value)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(public_key, crypto.SHA256, hash.Sum(nil), signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS): %w", err)
	}

	return nil
}

func (plugin *Plugin) BackgroundRefreshPublicKeys() {
	plugin.RefreshPublicKeys(plugin.cancelCtx)
	for {
		select {
		case <-plugin.cancelCtx.Done():
			plugin.logInfo(fmt.Sprint("Quit BackgroundRefreshPublicKeys: ", plugin.name))

			return
		case <-time.After(15 * time.Minute):
			plugin.RefreshPublicKeys(plugin.cancelCtx)
		}
	}
}

type Key struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Keys struct {
	Keys []Key `json:"keys"`
}

func (plugin *Plugin) RefreshPublicKeys(ctx context.Context) {
	fetched_public_keys := make(map[string]*rsa.PublicKey)

	for _, jwks_endpoint := range plugin.jwksEndpoints {
		plugin.logInfo(fmt.Sprint("RefreshPublicKeys - Endpoint: ", jwks_endpoint))
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwks_endpoint.String(), nil)
		if err != nil {
			plugin.logError(fmt.Sprint("RefreshPublicKeys - Failed to create request for endpoint: ", jwks_endpoint, "; error: ", err.Error()))

			continue
		}
		response, err := plugin.httpClient.Do(request)
		if err != nil {
			plugin.logError(fmt.Sprint("RefreshPublicKeys - Failed to request endpoint: ", jwks_endpoint, "; error: ", err.Error()))

			continue
		}
		body, err := io.ReadAll(response.Body)
		defer response.Body.Close()
		if err != nil {
			plugin.logError(fmt.Sprint("RefreshPublicKeys - Failed to read response for endpoint: ", jwks_endpoint, "; error: ", err.Error()))

			continue
		}
		var jwks_keys Keys
		err = json.Unmarshal(body, &jwks_keys)
		if err != nil {
			plugin.logError(fmt.Sprint("RefreshPublicKeys - Failed to parse response for endpoint: ", jwks_endpoint, "; error: ", err.Error()))

			continue
		}

		for _, key := range jwks_keys.Keys {
			switch key.Kty {
			case "RSA":
				{
					n_bytes, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						plugin.logError(fmt.Sprint("Failed to decode jwks key N", key.N, "; error: ", err.Error()))

						break
					}
					e_bytes, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						plugin.logError(fmt.Sprint("Failed to decode jwks key E", key.E, "; error: ", err.Error()))

						break
					}
					rsa_public_key := new(rsa.PublicKey)
					rsa_public_key.N = new(big.Int).SetBytes(n_bytes)
					rsa_public_key.E = int(new(big.Int).SetBytes(e_bytes).Uint64()) //nolint:gosec
					fetched_public_keys[key.Kid] = rsa_public_key
				}
			}
		}
	}

	plugin.public_keys_lock.Lock()
	defer plugin.public_keys_lock.Unlock()

	for kid, value := range fetched_public_keys {
		plugin.logInfo(fmt.Sprint("Register public key ", kid))
		plugin.public_keys[kid] = value
	}
}

type Log struct {
	Level      string `json:"level"`
	Message    string `json:"message"`
	PluginName string `json:"plugin_name"`
}

func (plugin *Plugin) logError(message string) {
	plugin.log("ERROR", message)
}

func (plugin *Plugin) logInfo(message string) {
	plugin.log("INFO", message)
}

func (plugin *Plugin) log(level string, message string) {
	log := Log{
		Level:      level,
		Message:    fmt.Sprint("Traefik-Oauth -", message),
		PluginName: plugin.name,
	}
	jsonlog, err := json.Marshal(log)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintln("Traefik-Oauth - Failed serialize", level, "log as JSON:", message)) //nolint:staticcheck
	} else {
		os.Stdout.WriteString(string(jsonlog) + "\n")
	}
}
