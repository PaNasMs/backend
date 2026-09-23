package systemops

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReadRequestRejectsOversized(t *testing.T) {
	big := strings.Repeat("a", MaxInput+1)
	body := `{"action":"x","params":{"k":"` + big + `"}}`
	_, err := ReadRequest(strings.NewReader(body))
	if !IsRejected(err) {
		t.Fatalf("oversized request: got %v, want rejection", err)
	}
}

func TestReadRequestRejectsMalformed(t *testing.T) {
	_, err := ReadRequest(strings.NewReader("{not json"))
	if !IsRejected(err) {
		t.Fatalf("malformed request: got %v, want rejection", err)
	}
}

func TestReadRequestKeepsBigIntegers(t *testing.T) {
	req, err := ReadRequest(strings.NewReader(`{"action":"a","params":{"size":18446744073709551615}}`))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	n, ok := req.Params["size"].(json.Number)
	if !ok || n.String() != "18446744073709551615" {
		t.Errorf("big integer lost precision: %#v", req.Params["size"])
	}
}

func TestWriteResultRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	huge := map[string]string{"x": strings.Repeat("y", MaxOutput+1)}
	if err := WriteResult(&buf, huge); !IsRejected(err) {
		t.Fatalf("oversized result: got %v, want rejection", err)
	}
	if buf.Len() != 0 {
		t.Errorf("oversized result wrote %d bytes; must emit nothing rather than truncated JSON", buf.Len())
	}
}

func TestRunUnknownMode(t *testing.T) {
	var out bytes.Buffer
	if err := Run("bogus", "u", strings.NewReader("{}"), &out, nil, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertErrorResult(t, out.Bytes(), "Unknown operation mode")
}

func TestRunNoHandler(t *testing.T) {
	var out bytes.Buffer
	if err := Run(ModeQuery, "u", strings.NewReader(`{"view":"x"}`), &out, nil, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertErrorResult(t, out.Bytes(), ErrNoRoute.Error())
}

func TestRunHandlerRejectionIsRedactedButValidationKept(t *testing.T) {
	var out bytes.Buffer
	h := func(Mode, string, *Request, *Reporter) (json.RawMessage, error) {
		return nil, reject("Invalid name")
	}
	if err := Run(ModePlan, "u", strings.NewReader("{}"), &out, nil, h); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertErrorResult(t, out.Bytes(), "Invalid name")

	out.Reset()
	h = func(Mode, string, *Request, *Reporter) (json.RawMessage, error) {
		return nil, io.ErrUnexpectedEOF // a non-rejection internal error
	}
	if err := Run(ModePlan, "u", strings.NewReader("{}"), &out, nil, h); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertErrorResult(t, out.Bytes(), "System handler error")
}

func TestRunHandlerCancelled(t *testing.T) {
	var out bytes.Buffer
	h := func(Mode, string, *Request, *Reporter) (json.RawMessage, error) {
		return nil, ErrCancelled
	}
	if err := Run(ModeExecute, "u", strings.NewReader("{}"), &out, nil, h); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	if !res.Cancelled || res.Error != "" {
		t.Errorf("expected {cancelled:true}, got %+v", res)
	}
}

func assertErrorResult(t *testing.T, data []byte, want string) {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("result is not valid JSON: %q", data)
	}
	var res Result
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.Error != want {
		t.Errorf("error = %q, want %q", res.Error, want)
	}
}
