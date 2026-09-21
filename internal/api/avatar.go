package api

import (
	"bytes"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"panasms.local/backend/internal/auth"
	"strings"
)

func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(identityKey{}).(auth.Identity).Username
	w.Header().Set("Cache-Control", "private, no-store")
	var version string
	var err error
	if r.Method == "PUT" {
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if e != nil {
			fail(w, 413, "Avatar must not exceed 2 MiB")
			return
		}
		config, format, e := image.DecodeConfig(bytes.NewReader(raw))
		if e != nil || (format != "png" && format != "jpeg") || config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > 4000000 {
			fail(w, 400, "Select a JPEG or PNG avatar up to 4 megapixels")
			return
		}
		source, _, e := image.Decode(bytes.NewReader(raw))
		if e != nil {
			fail(w, 400, "Could not read image")
			return
		}
		bounds := source.Bounds()
		side := min(bounds.Dx(), bounds.Dy())
		left := bounds.Min.X + (bounds.Dx()-side)/2
		top := bounds.Min.Y + (bounds.Dy()-side)/2
		thumb := image.NewRGBA(image.Rect(0, 0, 128, 128))
		for y := 0; y < 128; y++ {
			for x := 0; x < 128; x++ {
				thumb.Set(x, y, source.At(left+x*side/128, top+y*side/128))
			}
		}
		var output bytes.Buffer
		if jpeg.Encode(&output, thumb, &jpeg.Options{Quality: 90}) != nil {
			fail(w, 500, "Could not prepare avatar")
			return
		}
		version, err = s.Store.SaveAvatar(user, output.Bytes())
	} else if r.Method == "DELETE" {
		version, err = s.Store.SaveAvatar(user, nil)
	} else {
		var data []byte
		version, data, err = s.Store.Avatar(user)
		if strings.HasSuffix(r.URL.Path, "/image") {
			if err != nil || len(data) == 0 {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write(data)
			return
		}
	}
	if err != nil {
		fail(w, 500, "Could not save avatar")
		return
	}
	jsonResponse(w, 200, map[string]string{"version": version})
}
