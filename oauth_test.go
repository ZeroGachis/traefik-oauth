package traefik_oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreatePluginWithoutJwksEndpoints(t *testing.T) {
	cfg := CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	_, err := New(ctx, next, cfg, "sw-oauth-plugin")
	if err != nil {
		t.Fail()
	}
}

func TestFailToCreatePluginWithMalformedJwksEndpoint(t *testing.T) {
	cfg := CreateConfig()
	cfg.JwksEndpoints = []string{"not an url"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	_, err := New(ctx, next, cfg, "sw-oauth-plugin")

	if err.Error() != "failed to parse jwks endpoints" {
		t.Fail()
	}
}

const (
	private_key_pem               = `-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDlrh93dWNGQ0KT\ny8rzMzLXZje2hkWTnKHXwqbjoSBpRE2OOkRp3E/aXuUVzSbsfxIGF3xHco5cKzhy\n+er4tT9MzA7DEhEuHVJaritWtaGpcWmsYZCT+4Oc5tFf2RnWAJrvA90/BJulappg\nhR1M6s5PGTwe/US+sHrbDha55suv3LeSerTYIMA19HHA6YrRfKuZpb+hAmhMScsV\nSv77GNLKT0No3gJvv8GGf0JliSLSEa7davkYvS5x1KjxrgW+6PRr+pgu6eatB47x\nAMt8x0d2Q4CQhOuT1acQTQbT4JHksu8vWqIWjTtEqQ47HaVuYq13z6cNQGtaARf7\nWUhPSzBXAgMBAAECggEAZVsuxa/G7IXYBpLjb+mDIS0ZnvGoGJkBjs52iXNcczfS\nJdauxCyWDJ7d534OFEWLNab9kCYMjr3//jUtrS2GzqQqS4lYjYohAqVjuLMUsUq8\nQHcZr0RJ816kvPB4h0jjFmEVLK8i5J+jmr6DjKL+Akf3kRFhWelVff+8pbMk5eji\nDmZdcgDfxjJvo97bZL0GlM+SY8p391bRLyU9Vmus3dYdgyGxyiYF155zFDWk2xFB\nX1x7L2+4EueMlqu/q/2tGc8s3fmJVqa5pPVfqQtCCR536J5TOsa2Hjgc/vNAUfPJ\n3i310jhwmK4SNKY4qilHQLoHduteIMJDJ6DfMeq90QKBgQD1M2N81inH5phc9VIw\nMpVVlV9NQnaEKVnxlSfe15XM3OSG6FFFkvprqd96Oh59uZGu1DGoTf6qB0x1RGMH\n9ArWMGjEpQPJZy0JBeq/y1iM4++RibHRnNC9RHWrKCpe7FB7RjoP+AYbVWstPlkh\n8sQL5EN5KiLWpaBjdbBt1OcrGQKBgQDvy73YM9UWboQMUAjo/HZgazyenaI+bO4g\ntDU/4kiU6cm0AJi7hLByCjm7vGjtVkQkHC9+hUSf9QUstWy2nADwm1MrAoR1qg3l\nUNzgPIUfdb3DrdqnPLWKf910e0OhEN4PO1EYhZg+3H8rhWqYYyCkKTftVQnVErKw\nvAtP/HwU7wKBgQDsILjGF1fU8fP4USb80zmMWXSValPHoirDwufKacIQrwhEAqWB\nYrFVzRkxE5cZbAMnYaEQe0urYav3ogvcNN/atHOwK1kiMwHjlpcibCiyRS8H8JoV\nSfaazbqjQOLM1rYKgO6ZQjhfSjsULt6XGrpA2WlA3Zr/KjDylvt4SXb0wQKBgAQy\nYak2BwW0e3UntXA2cu/vEImKIrvK9kP2Q3RRxolsqg4PcJzfjqMAUNBbVM7Kkri7\nEY26UWAnTqbgqf1sL4wGe+clzSGuDz4zMxptlLrfOaoCEfCZXGgHIt4WBjH8dJZ5\nqEqwk+CNxWACnsH6Aik9W3A468oh4KS9Ncl5lsZbAoGBAPRl7kaFuZQRF6WNKmpq\nt4lSw5NrxyB/SgTUh/uFL5unQKYr6e7LAHYOSvxGdsp1TIiQnc6zKJwA8MRWZUm0\nUkD+rIEFYB7g/cZSPkQfHOC+DLTOTLmX736gBShoKsH7Q1SSqKyhLDCUv9Xp7RHs\naTf5bOMQeFg9wgcggpTZirws\n-----END PRIVATE KEY-----\n`
	jwk                           = `{"e":"AQAB","kid":"EC7db_1I1Z8QhOsQW4JXxfFdZcUg8QHjyDpBd9qheow","kty":"RSA","n":"5a4fd3VjRkNCk8vK8zMy12Y3toZFk5yh18Km46EgaURNjjpEadxP2l7lFc0m7H8SBhd8R3KOXCs4cvnq-LU_TMwOwxIRLh1SWq4rVrWhqXFprGGQk_uDnObRX9kZ1gCa7wPdPwSbpWqaYIUdTOrOTxk8Hv1EvrB62w4WuebLr9y3knq02CDANfRxwOmK0XyrmaW_oQJoTEnLFUr--xjSyk9DaN4Cb7_Bhn9CZYki0hGu3Wr5GL0ucdSo8a4Fvuj0a_qYLunmrQeO8QDLfMdHdkOAkITrk9WnEE0G0-CR5LLvL1qiFo07RKkOOx2lbmKtd8-nDUBrWgEX-1lIT0swVw"}`
	access_token_without_exp      = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkVDN2RiXzFJMVo4UWhPc1FXNEpYeGZGZFpjVWc4UUhqeURwQmQ5cWhlb3ciLCJ0eXAiOiJKV1QifQ.e30.l7pt-bFz6WuHd-gFIbvFYh1sadaPe4VlzmB6iGtacnhUqv6Daj4muVp7IlHx-moF0PBo4sJGOadeLeAhDaiZyO45FoAqeR-UiTPyrYEVzsqDufVZV3sRrotxyM5MgEXymqTETDeVBUedjb6rOONmwHzw2s1w8CW81tv_EFifmYgYW2VJXAEXj0Dt6EdUncP2vbOYlp7bavAUySjdWs-Ew_R4boZLLLTrYOe45nGiXFlBYuJZ5VWWvc6H_xfN0Sr-BSiscgEzt0p7hYLhDBuE-OJCB6BuoJiEwHJhJpyXMZ1LePrWOlqq6q6THENpO_ZlNUJhBs_PV2MgXT6fzkSUpg`                      //nolint:gosec
	access_token_with_long_exp    = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkVDN2RiXzFJMVo4UWhPc1FXNEpYeGZGZFpjVWc4UUhqeURwQmQ5cWhlb3ciLCJ0eXAiOiJKV1QifQ.eyJleHAiOjIwNzQzMTg4ODl9.P2EkowfPeDQNtjB57o6nY2NVuIlBh3-ADZMAvpSINHRzGLCLaCG4CwuGIgFqJPwoCd3hU2Ns_dzjIakBEcSduCobfrlxDVWGHVoCJ5daceuESlQVcbwWuHBjD7Jr3oG_tWRP15UQzsWbym9-DcjwC72v_q3xQnXvMMdMeVVXrINFxEpWM-Uc2ttF7DCEDhQW2RfMHxldNBXaD0p14ejfuE6x6Fibbh58GGc0A1KIQ0cAJjth3y4gXWeEQspJwJqQkGbOz_im70cNylU6cdJNLgTzLIbYcfBkbXQbbqkCqu9U_kDZUFiqI5WHe7X3b8eAJLlkoylEGoB3q2xggrylUw` //nolint:gosec
	access_token_with_expired_exp = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkVDN2RiXzFJMVo4UWhPc1FXNEpYeGZGZFpjVWc4UUhqeURwQmQ5cWhlb3ciLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NTYxMDc2ODl9.E1ZVy7KbCroW8m1ie5TDs60JYXMswtTFSeTyJzfW-DC9SsgOy-B0TNMo92OST826XI7cchWOMu1QqqYuH8vsvzLulBSMXoS1cnqmOoKcAvP_Lchk64a2m-ebp91MA771zXjLMAVjJxd_GWpyWMa_XbecErFFHvfI7glZN42qgEtAK5nCi8CHcQxcXl4YYhzKTSnn1GFDSS9t2fmXiq4ZIeGaCkPuSscC0rdbtMXtjIKsYgfuYqBw5zcQ3WNs8QCGaVHBarZfQ8U4ohYu7-qaMi7Jb25ciOqMeOXz96-bYZnwyENv7fQqb3xJ_GqmMg7iXs0n-keVUkd6UiGDUI80gA` //nolint:gosec
)

func setupTestJwksServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		jwks := fmt.Sprintf(`{"keys":[%s]}`, jwk)
		_, _ = fmt.Fprintln(w, jwks)
	}))
}

func setupWorkingPlugin(t *testing.T, ctx context.Context, jwks_endpoints []string) http.Handler {
	t.Helper()

	cfg := CreateConfig()
	cfg.JwksEndpoints = jwks_endpoints

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(rw, "It worked")
	})

	handler, err := New(ctx, next, cfg, "sw-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	return handler
}

func TestForwardRequestWithAValidJwtToken(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header["Authorization"] = []string{access_token_with_long_exp}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()

	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK && string(body) != "It worked" {
		t.Errorf("Got status code %d, %s", recorder.Code, body)
	}
}

func TestFailWhenJwtTokenHasNoExpiry(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header["Authorization"] = []string{access_token_without_exp}

	handler.ServeHTTP(recorder, req)

	response := recorder.Result()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got  %d", recorder.Code)
	}
}

func TestFailWhenJwtTokenHasExpired(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header["Authorization"] = []string{access_token_with_expired_exp}

	handler.ServeHTTP(recorder, req)

	response := recorder.Result()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got  %d", recorder.Code)
	}
}

func TestFailWhenJwtTokenIsMalformed(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header["Authorization"] = []string{"Bearer value"}

	handler.ServeHTTP(recorder, req)

	response := recorder.Result()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got  %d", recorder.Code)
	}
}

func TestFailWhenAuthorizationHeaderIsNotBearer(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header["Authorization"] = []string{"Basic value"}

	handler.ServeHTTP(recorder, req)

	response := recorder.Result()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got  %d", recorder.Code)
	}
}

func TestFailWithMissingAuthorizationHeader(t *testing.T) {
	test_jwks_server := setupTestJwksServer()
	defer test_jwks_server.Close()

	ctx := context.Background()

	handler := setupWorkingPlugin(t, ctx, []string{test_jwks_server.URL})
	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	response := recorder.Result()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got  %d", recorder.Code)
	}
}
