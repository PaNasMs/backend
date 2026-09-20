package transfer

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransferCompletesOnlyAfterProducerSuccess(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		size       int64
		failure    bool
	}{
		{"empty", "", 0, false}, {"complete", strings.Repeat("a", 100000), 100000, false},
		{"truncated", strings.Repeat("a", 70000), 100000, false},
		{"grew", strings.Repeat("a", 100001), 100000, false},
		{"failed at EOF", strings.Repeat("a", 100000), 100000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Stream(w, strings.NewReader(tc.body), tc.size, func() error {
					if tc.failure {
						return errors.New("producer failed")
					}
					return nil
				})
			}))
			defer s.Close()
			response, err := s.Client().Get(s.URL)
			var data []byte
			if err == nil {
				defer response.Body.Close()
				data, err = io.ReadAll(response.Body)
			}
			success := int64(len(tc.body)) == tc.size && !tc.failure
			if success && (err != nil || string(data) != tc.body) {
				t.Fatal("valid transfer failed", err)
			}
			if !success && err == nil {
				t.Fatal("broken transfer reported success")
			}
		})
	}
}
