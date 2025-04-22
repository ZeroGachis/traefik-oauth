package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwardRequest(t *testing.T) {
	cfg := CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "sw-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Result().StatusCode != http.StatusOK {
		t.Errorf("Got status code %d", recorder.Code)
	}
}
