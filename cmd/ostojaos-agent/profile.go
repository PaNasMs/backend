package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/profile"
	"strings"
)

func profileHandler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.Lookup(r.URL.Query().Get("user"), allowed)
		if err != nil {
			http.Error(w, "access denied", 403)
			return
		}
		if r.Method == "GET" {
			p, err := profile.Read(r.Context(), id.Username)
			if err != nil {
				http.Error(w, "profile unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(p)
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var body struct {
			Action  string `json:"action"`
			Name    string `json:"name"`
			Current string `json:"currentPassword"`
			Next    string `json:"newPassword"`
			Key     string `json:"key"`
			ID      string `json:"id"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 24000)
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		if body.Action != "name" {
			if body.Current == "" || len(body.Current) > 4096 || strings.ContainsRune(body.Current, 0) || auth.Authenticate(id.Username, body.Current) != nil {
				http.Error(w, "current password incorrect", 403)
				return
			}
		}
		switch body.Action {
		case "name":
			if !profile.ValidName(body.Name) {
				http.Error(w, "invalid name", 400)
				return
			}
			err = profile.SetName(r.Context(), id.Username, body.Name)
		case "password":
			if body.Next == "" || len(body.Next) > 4096 || strings.ContainsAny(body.Next, "\x00\n\r") {
				http.Error(w, "invalid password", 400)
				return
			}
			err = auth.ChangePassword(id.Username, body.Current, body.Next)
		case "add", "delete":
			_, err = profile.Keys(r.Context(), id.Username, map[string]string{"action": body.Action, "key": body.Key, "id": body.ID})
		default:
			http.Error(w, "unknown action", 400)
			return
		}
		if err != nil {
			http.Error(w, "profile update failed", 400)
			return
		}
		log.Printf("profile action=%s user=%s", body.Action, id.Username)
		w.WriteHeader(204)
	}
}
