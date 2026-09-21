package api

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"panasms.local/backend/internal/auth"
	"testing"
)

func TestAvatarUploadIsolationAndValidation(t *testing.T) {
	s := testServer(t)
	call := func(user, method, path string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: user}))
		w := httptest.NewRecorder()
		if path == "/image" {
			s.avatar(w, r)
		} else {
			s.avatar(w, r)
		}
		return w
	}
	var pngData bytes.Buffer
	png.Encode(&pngData, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	if w := call("alice", http.MethodPut, "/", pngData.Bytes()); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("alice", http.MethodGet, "/image", nil); w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatal(w.Code)
	}
	if w := call("bob", http.MethodGet, "/image", nil); w.Code != 404 {
		t.Fatal("leaked wallpaper", w.Code)
	}
	for _, raw := range [][]byte{[]byte("<svg></svg>"), pngData.Bytes()[:32], make([]byte, (2<<20)+1)} {
		if w := call("alice", http.MethodPut, "/", raw); w.Code < 400 {
			t.Fatal("invalid image accepted")
		}
	}
	if w := call("alice", http.MethodGet, "/image", nil); w.Code != 200 {
		t.Fatal("bad upload removed existing wallpaper")
	}
	call("bob", http.MethodDelete, "/", nil)
	if w := call("alice", http.MethodGet, "/image", nil); w.Code != 200 {
		t.Fatal("cross user deletion")
	}
	call("alice", http.MethodDelete, "/", nil)
	if w := call("alice", http.MethodGet, "/image", nil); w.Code != 404 {
		t.Fatal("delete failed")
	}
}
