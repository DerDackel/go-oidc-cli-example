package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallbackDeliversCode(t *testing.T) {
	results := make(chan callbackResult, 1)
	handler := callbackHandler("expected-state", results)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=expected-state", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
	result := <-results
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if result.code != "abc" {
		t.Errorf("code: got %q, want %q", result.code, "abc")
	}
}

func TestCallbackRejectsWrongState(t *testing.T) {
	results := make(chan callbackResult, 1)
	handler := callbackHandler("expected-state", results)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=forged", nil))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", rec.Code)
	}
	result := <-results
	if result.err == nil {
		t.Fatal("a forged state must produce an error")
	}
	if result.code != "" {
		t.Errorf("code must not be accepted, got %q", result.code)
	}
}

func TestCallbackReportsProviderError(t *testing.T) {
	results := make(chan callbackResult, 1)
	handler := callbackHandler("expected-state", results)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/callback?error=access_denied&error_description=user+said+no&state=expected-state", nil))

	result := <-results
	if result.err == nil {
		t.Fatal("an error response must produce an error")
	}
	if !strings.Contains(result.err.Error(), "access_denied") ||
		!strings.Contains(result.err.Error(), "user said no") {
		t.Errorf("error does not carry the provider details: %v", result.err)
	}
}

func TestCallbackIgnoresOtherPaths(t *testing.T) {
	results := make(chan callbackResult, 1)
	handler := callbackHandler("expected-state", results)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
	select {
	case result := <-results:
		t.Fatalf("an unrelated request must not end the login, got %+v", result)
	default:
	}
}
