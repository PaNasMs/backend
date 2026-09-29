package notify

import (
	"encoding/json"
	"testing"
)

func TestRoutesAllowMultipleDistinctChannels(t *testing.T) {
	p := Defaults()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Routes["critical"] = Channels{"email", "telegram"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Routes["critical"] = Channels{"email", "email"}
	if p.Validate() == nil {
		t.Fatal("allowed duplicate channels")
	}
	p = Defaults()
	p.Email = "x@example.org\r\nBcc: attacker@example.org"
	if p.Validate() == nil {
		t.Fatal("header injection")
	}
	p = Defaults()
	p.ChatID = "-100123456"
	if p.Validate() == nil {
		t.Fatal("shared chat leaks personal notifications")
	}
}
func TestMessagesAreLocalizedAndFallbackIsEnglish(t *testing.T) {
	e := Event{Kind: "cpu-hot", Severity: "critical"}
	en, ru, uk := e.Message("en"), e.Message("ru"), e.Message("uk")
	if en.Body == ru.Body || ru.Body == uk.Body || e.Message("invalid").Body != en.Body {
		t.Fatal(en, ru, uk)
	}
	if ru.Body != "Температура процессора достигла 80 °C." {
		t.Fatal(ru)
	}
}
func TestPushRejectsSSRFAndBadKeys(t *testing.T) {
	for _, endpoint := range []string{"http://fcm.googleapis.com/", "https://127.0.0.1/", "https://fcm.googleapis.com.evil.test/", "https://user:pass@fcm.googleapis.com/", "https://fcm.googleapis.com:444/"} {
		s := Subscription{Endpoint: endpoint}
		if s.Validate() == nil {
			t.Fatal(endpoint)
		}
	}
}
func TestSMTPRequiresEncryptedConnection(t *testing.T) {
	c := Config{SMTP: SMTP{Enabled: true, Host: "smtp.test", Port: 25, Security: "plain", From: "nas@example.org"}}
	if c.Validate() == nil {
		t.Fatal("plaintext smtp accepted")
	}
}

func TestLegacyRoutesRemainCompatible(t *testing.T) {
	var p Preferences
	if err := json.Unmarshal([]byte(`{"routes":{"info":"panel","warning":"push","error":"email","critical":"telegram"}}`), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(p.Routes["info"]) != 0 || len(p.Routes["critical"]) != 1 || p.Routes["critical"][0] != "telegram" {
		t.Fatal(p)
	}
	raw, _ := json.Marshal(p)
	var decoded struct{ Routes map[string][]string }
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
}
