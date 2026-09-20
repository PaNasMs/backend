package api

import (
	"bytes"
	"database/sql"
	"errors"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"ostojaos.local/backend/internal/auth"
)

func (s *Server) wallpaper(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(identityKey{}).(auth.Identity).Username
	w.Header().Set("Cache-Control", "private, no-store")
	var version string
	var err error
	switch r.Method {
	case http.MethodPut:
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if readErr != nil {
			fail(w, 413, "The image must not exceed 8 MiB")
			return
		}
		cfg, format, decodeErr := image.DecodeConfig(bytes.NewReader(raw))
		if decodeErr != nil || (format != "jpeg" && format != "png") {
			fail(w, 400, "Select a JPEG or PNG image")
			return
		}
		if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > 24000000 {
			fail(w, 400, "The image must not exceed 24 megapixels")
			return
		}
		img, _, decodeErr := image.Decode(bytes.NewReader(raw))
		if decodeErr != nil {
			fail(w, 400, "Could not read image")
			return
		}
		var output bytes.Buffer
		if jpeg.Encode(&output, img, &jpeg.Options{Quality: 90}) != nil {
			fail(w, 500, "Could not prepare wallpaper")
			return
		}
		version, err = s.Store.SaveWallpaper(user, output.Bytes())
	case http.MethodDelete:
		version, err = s.Store.SaveWallpaper(user, nil)
	default:
		version, err = s.Store.WallpaperVersion(user)
	}
	if err != nil {
		fail(w, 500, "Could not save or read wallpaper")
		return
	}
	jsonResponse(w, 200, map[string]string{"version": version})
}

func (s *Server) wallpaperImage(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(identityKey{}).(auth.Identity).Username
	w.Header().Set("Cache-Control", "private, no-store")
	data, err := s.Store.Wallpaper(user)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		fail(w, 500, "Could not read wallpaper")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}
