package auth

import (
	"fmt"
	"net/http"
)

// callbackResult carries the outcome of the redirect back from the browser.
type callbackResult struct {
	code string
	err  error
}

// callbackHandler serves the loopback redirect URI. It compares the state
// parameter, reports errors from the provider and hands the authorization code
// to the waiting login.
func callbackHandler(expectedState string, results chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if errCode := q.Get("error"); errCode != "" {
			err := fmt.Errorf("authorization failed: %s", errCode)
			if desc := q.Get("error_description"); desc != "" {
				err = fmt.Errorf("authorization failed: %s: %s", errCode, desc)
			}
			writePage(w, http.StatusBadRequest, "Login failed", err.Error())
			send(results, callbackResult{err: err})
			return
		}

		// The state binds the redirect to this CLI invocation and protects
		// against a forged authorization response.
		if q.Get("state") != expectedState {
			err := fmt.Errorf("authorization failed: state parameter mismatch")
			writePage(w, http.StatusBadRequest, "Login failed", err.Error())
			send(results, callbackResult{err: err})
			return
		}

		code := q.Get("code")
		if code == "" {
			err := fmt.Errorf("authorization failed: no code in the redirect")
			writePage(w, http.StatusBadRequest, "Login failed", err.Error())
			send(results, callbackResult{err: err})
			return
		}

		writePage(w, http.StatusOK, "Login successful", "You can close this tab and return to the terminal.")
		send(results, callbackResult{code: code})
	})
	// Anything else, for example the favicon request of the browser, must not
	// end the login.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// send delivers a result without blocking if one was already delivered.
func send(results chan<- callbackResult, result callbackResult) {
	select {
	case results <- result:
	default:
	}
}

func writePage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>%s</title></head>
<body style="font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 32rem;">
<h1>%s</h1>
<p>%s</p>
</body>
</html>
`, title, title, message)
}
