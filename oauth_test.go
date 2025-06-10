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
	jwk       = `{"alg":"RSA-256","e":"AQAB","kid":"12345","kty":"RSA","n":"sSz5k-1r8fFk1b4D0fhhwshr5YcKQ3WLeSpQ8N-P8U0u7gYT0SWHOesHCElrteVRv1kG1BO5LvB7vJQlGu3fK2uBIsvF0R52c4wtarrczwrLde93jzwXJpvpGleORcyFh0ekRBI-I1BlymLOwoWsF5UmeQEQIgicgW2xNWpLJ4zhWx0mQQ-S1cnxFf7cwklpeo61ykwgHV3-SwH8l7T2Z9gjtMDLJo-iP5GsOv_4UC-ZLGtdrJFfRSkKebukr2IXwFtyw9t-X6EMlhpGtw1ABvbf8V_OBVaV4SV_3ONoU48G-DWuvno609RuFsKcMIjdSZO3-2GmxSb-TUmoFc6J_w","use":"sig"}` //nolint:lll
	jwt_token = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1In0.e30.hkm8A8LvxdVjUmcShtch8KSO2frA94KnxriioePyGTFuJ_-wzdKdgEdETdWNFx4masf6oSUi6EeMTt--f1BC6mUwXdGCASzXGw5cYAynZZGi6O26GbxCNQ83pHfk_NCjHmXtjSCbVCHpOi9adHJU9A5UH8Bvn_4wCfJo8h1lQC0Nu6Vu6j4k1oCsjgm-eoRdmovm97wnela2yU19GTz_4gGue_kfG9cYwHltnnns-aVNiatI-ug7ULtQqHXP6RZydFmzAmzyf-XE5ZGxzmgaCpmA67bF4I9xSlNyvL3gSBNuvilxSdJCLEOBfJGNsEyXOgIoFtoCIrb1C0aFVkSr3Q`                       //nolint:gosec
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
	req.Header["Authorization"] = []string{jwt_token}

	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK && string(body) != "It worked" {
		t.Errorf("Got status code %d, %s", recorder.Code, body)
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
