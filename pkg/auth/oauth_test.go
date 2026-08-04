// File: pkg/auth/oauth_test.go

package auth

import (
	"strings"
	"testing"
)

// The OAuth callback page reflects the `error` and `error_description` query
// parameters of http://localhost:9877/callback. That branch runs before the
// state check, so any page open in the user's browser can reach it during the
// login window. The reflected values must never be able to close a tag.
func TestCallbackErrorBodyEscapesReflectedInput(t *testing.T) {
	payload := `<script>alert(document.domain)</script>`

	body := callbackErrorBody("Authorization denied", "access_denied: "+payload)

	if strings.Contains(body, payload) {
		t.Fatalf("callbackErrorBody reflected the raw payload:\n%s", body)
	}
	if strings.Contains(body, "<script") {
		t.Fatalf("callbackErrorBody emitted a <script tag:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("callbackErrorBody did not HTML-escape the payload:\n%s", body)
	}
}

func TestCallbackErrorBodyEscapesTitle(t *testing.T) {
	body := callbackErrorBody(`</h1><img src=x onerror=alert(1)>`, "detail")

	if strings.Contains(body, "<img") {
		t.Fatalf("callbackErrorBody emitted an <img tag:\n%s", body)
	}
	if !strings.Contains(body, "&lt;/h1&gt;") {
		t.Fatalf("callbackErrorBody did not HTML-escape the title:\n%s", body)
	}
}

func TestCallbackErrorBodyEscapesAttributeBreakingCharacters(t *testing.T) {
	body := callbackErrorBody("t", `" onmouseover="alert(1)`)

	if strings.Contains(body, `" onmouseover="`) {
		t.Fatalf("callbackErrorBody left a raw double quote in the output:\n%s", body)
	}
	if !strings.Contains(body, "&#34;") {
		t.Fatalf("callbackErrorBody did not escape the double quote:\n%s", body)
	}
}

// The static bodies must survive escaping unchanged — the fix must not mangle
// the messages the CLI itself produces.
func TestCallbackErrorBodyKeepsPlainMessagesIntact(t *testing.T) {
	body := callbackErrorBody("Security check failed", "Invalid state parameter. Please try logging in again.")

	if !strings.Contains(body, "<h1>Security check failed</h1>") {
		t.Fatalf("plain title was altered:\n%s", body)
	}
	if !strings.Contains(body, "Invalid state parameter. Please try logging in again.") {
		t.Fatalf("plain detail was altered:\n%s", body)
	}
}
