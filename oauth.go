package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	PublicKeys map[string]string
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next        http.Handler
	name        string
	public_keys map[string]*rsa.PublicKey
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	plugin := &Plugin{
		next:        next,
		name:        name,
		public_keys: make(map[string]*rsa.PublicKey),
	}

	if len(config.PublicKeys) > 0 {
		if err := plugin.ParsePublicKeys(config.PublicKeys); err != nil {
			return nil, err
		}
	}

	return plugin, nil
}

func (plugin *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := plugin.ValidateToken(req, rw); err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}
	plugin.next.ServeHTTP(rw, req)
}

func (plugin *Plugin) ParsePublicKeys(public_keys map[string]string) error {
	for kid, pem_public_key := range public_keys {
		block, _ := pem.Decode([]byte(pem_public_key))
		if block == nil {
			return errors.New("Fail to decode public key's PEM")
		}

		if block.Type != "PUBLIC KEY" {
			return errors.New("PEM is not of type RSA")
		}

		public_key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to parse RSA public key: kid=%s, error=%w", kid, err)
		}
		var rsa_public_key *rsa.PublicKey
		var ok bool
		if rsa_public_key, ok = public_key.(*rsa.PublicKey); !ok {
			return fmt.Errorf("Public key is not RSA: kid=%s", kid)
		}

		plugin.public_keys[kid] = rsa_public_key
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
		return errors.New("Authorization header missing")
	}

	if !strings.HasPrefix(authorization_header[0], "Bearer ") {
		return errors.New("Authorization header type is not bearer")
	}
	jwt_token := authorization_header[0][7:]

	parts := strings.Split(jwt_token, ".")
	if len(parts) != 3 {
		return errors.New("Invalid token format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("JWT header is not base64 encoded")
	}
	_, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("JWT payload is not base64 encoded")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("JWT signature is not base64 encoded")
	}

	var jwt_header JwtHeader
	err = json.Unmarshal(header, &jwt_header)
	if err != nil {
		return err
	}
	if jwt_header.Algorithm != "RS256" {
		return errors.New("JWT must use RS256 algorithm")
	}

	public_key, ok := plugin.public_keys[jwt_header.Kid]
	if !ok {
		return fmt.Errorf("No signature for kid=%s", jwt_header.Kid)
	}
	jwt_token_header_and_payload := jwt_token[0 : len(parts[0])+len(parts[1])+1]
	err = VerifySignature(public_key, []byte(jwt_token_header_and_payload), signature)
	if err != nil {
		return fmt.Errorf("Invalid signature %w", err)
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
