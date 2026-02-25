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
	"time"
)

type Config struct {
	JwksEndpoints []string
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next          http.Handler
	name          string
	public_keys   map[string]*rsa.PublicKey
	jwksEndpoints []*url.URL
	httpClient    *http.Client
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	plugin := &Plugin{
		next:          next,
		name:          name,
		public_keys:   make(map[string]*rsa.PublicKey),
		jwksEndpoints: []*url.URL{},
		httpClient:    &http.Client{},
	}

	err := plugin.ParseJwksEndpoints(config.JwksEndpoints)
	if err != nil {
		plugin.logError(err.Error())

		return nil, errors.New("failed to parse jwks endpoints")
	}

	err = plugin.RefreshPublicKeys(ctx)
	if err != nil {
		plugin.logError(fmt.Sprint("RefreshPublicKeys - Failed: ", err))
	}

	return plugin, nil
}

func (plugin *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := plugin.ValidateToken(req, rw)
	if err != nil {
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
		validationError := errors.New("authorization header missing")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	if !strings.HasPrefix(authorization_header[0], "Bearer ") {
		validationError := errors.New("authorization header type is not bearer")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	jwt_token := authorization_header[0][7:]

	parts := strings.Split(jwt_token, ".")
	if len(parts) != 3 {
		validationError := errors.New("invalid token format")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		validationError := errors.New("jwt header is not base64 encoded")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		validationError := errors.New("jwt payload is not base64 encoded")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		validationError := errors.New("jwt signature is not base64 encoded")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	var jwt_header JwtHeader

	err = json.Unmarshal(header, &jwt_header)
	if err != nil {
		return err
	}

	if jwt_header.Algorithm != "RS256" {
		validationError := errors.New("jwt must use RS256 algorithm")
		plugin.logWarning(validationError.Error())

		return validationError
	}

	public_key, ok := plugin.public_keys[jwt_header.Kid]
	if !ok {
		validationError := fmt.Errorf("no signature for kid=%s", jwt_header.Kid)
		plugin.logWarning(validationError.Error())

		return validationError
	}

	jwt_token_header_and_payload := jwt_token[0 : len(parts[0])+len(parts[1])+1]

	err = VerifySignature(public_key, []byte(jwt_token_header_and_payload), signature)
	if err != nil {
		validationError := fmt.Errorf("invalid signature %w", err)
		plugin.logWarning(validationError.Error())

		return validationError
	}

	ok, err = plugin.VerifyExpiry(payload)
	if err != nil {
		plugin.logWarning(err.Error())

		return err
	}

	if !ok {
		validationError := errors.New("JWT token expiry reached")
		plugin.logDebug(validationError.Error())

		return validationError
	}

	return nil
}

func VerifySignature(public_key *rsa.PublicKey, value []byte, signature []byte) error {
	hash := crypto.SHA256.New()

	_, err := hash.Write(value)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(public_key, crypto.SHA256, hash.Sum(nil), signature)
	if err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS): %w", err)
	}

	return nil
}

type JwtPayload struct {
	Exp int64 `json:"exp"`
}

func (plugin *Plugin) VerifyExpiry(payload []byte) (bool, error) {
	var jwt_payload JwtPayload

	err := json.Unmarshal(payload, &jwt_payload)
	if err != nil {
		return false, fmt.Errorf("failed to parse jwt token payload %w", err)
	}

	expiry := jwt_payload.Exp
	if expiry == 0 {
		return false, nil
	}

	now := time.Now().Unix()
	if expiry > now {
		return true, nil
	} else {
		return false, nil
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

func (plugin *Plugin) RefreshPublicKeys(ctx context.Context) error {
	fetched_public_keys := make(map[string]*rsa.PublicKey)

	for _, jwks_endpoint := range plugin.jwksEndpoints {
		plugin.logDebug(fmt.Sprint("RefreshPublicKeys - Endpoint: ", jwks_endpoint))

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwks_endpoint.String(), nil)
		if err != nil {
			return err
		}

		response, err := plugin.httpClient.Do(request)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(response.Body)
		defer response.Body.Close()

		if err != nil {
			return err
		}

		var jwks_keys Keys

		err = json.Unmarshal(body, &jwks_keys)
		if err != nil {
			return err
		}

		for _, key := range jwks_keys.Keys {
			if key.Kty == "RSA" {
				n_bytes, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return err
				}

				e_bytes, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					return err
				}

				rsa_public_key := new(rsa.PublicKey)
				rsa_public_key.N = new(big.Int).SetBytes(n_bytes)
				rsa_public_key.E = int(new(big.Int).SetBytes(e_bytes).Uint64()) //nolint:gosec
				fetched_public_keys[key.Kid] = rsa_public_key
			}
		}
	}

	for kid, value := range fetched_public_keys {
		plugin.logDebug(fmt.Sprint("Register public key ", kid))
		plugin.public_keys[kid] = value
	}

	return nil
}

type Log struct {
	Level      string `json:"level"`
	Message    string `json:"message"`
	PluginName string `json:"plugin_name"`
}

func (plugin *Plugin) logError(message string) {
	plugin.log("ERROR", message)
}

func (plugin *Plugin) logWarning(message string) {
	plugin.log("WARNING", message)
}

func (plugin *Plugin) logDebug(message string) {
	plugin.log("DEBUG", message)
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
