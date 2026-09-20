package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"panasms.local/backend/internal/auth"
	"strings"
	"testing"
)

type thumbnailTransport func(*http.Request) (*http.Response, error)

func (f thumbnailTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestThumbnailUsesAuthenticatedUserAndInlineImage(t *testing.T) {
	s := testServer(t)
	s.ModuleClient = func(string) (*http.Client, error) { return s.Agent, nil }
	s.Agent = &http.Client{Transport: thumbnailTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("user") != "alice" || r.URL.Query().Get("thumbnail") != "1" || r.URL.Query().Get("target") != "/home/alice/a.png" {
			t.Fatalf("incorrect agent request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, ContentLength: 9, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("thumbnail"))}, nil
	})}
	req := httptest.NewRequest("GET", "/api/v1/files/content?thumbnail=1&user=root&target=/home/alice/a.png", nil)
	req = req.WithContext(context.WithValue(req.Context(), identityKey{}, auth.Identity{Username: "alice"}))
	out := httptest.NewRecorder()
	s.files(out, req)
	if out.Code != 200 || out.Header().Get("Content-Type") != "image/jpeg" || out.Header().Get("Content-Disposition") != "" || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response: %d %v", out.Code, out.Header())
	}
}

func TestDownloadPropagatesLengthAndAbortsTruncation(t *testing.T) {
	for _, body := range []string{"complete", "short"} {
		t.Run(body, func(t *testing.T) {
			s := testServer(t)
			s.ModuleClient = func(string) (*http.Client, error) { return s.Agent, nil }
			s.Agent = &http.Client{Transport: thumbnailTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, ContentLength: 8, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			req := httptest.NewRequest("GET", "/api/v1/files/content?target=/home/alice/a", nil)
			req = req.WithContext(context.WithValue(req.Context(), identityKey{}, auth.Identity{Username: "alice"}))
			out := httptest.NewRecorder()
			defer func() {
				v := recover()
				if body == "short" && v != http.ErrAbortHandler {
					t.Fatal("truncation not aborted", v)
				}
				if body == "complete" && v != nil {
					t.Fatal(v)
				}
				if out.Header().Get("Content-Length") != "8" {
					t.Fatal("missing length")
				}
			}()
			s.files(out, req)
		})
	}
}
