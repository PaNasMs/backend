package notify

import (
	"strings"
	"testing"
)

const testCatalog = `{"actions":{"file.copy":{"en":"Copy","ru":"Копировать","uk":"Копіювати"}},
"messages":[
 {"source":["Not enough free space","Недостаточно свободного места"],"en":"Not enough free space","ru":"Недостаточно свободного места","uk":"Недостатньо вільного місця"},
 {"source":["Command {{v0}} exited with code {{v1}}."],"en":"Command {{v0}} exited with code {{v1}}.","ru":"Команда {{v0}} завершилась с кодом {{v1}}.","uk":"Команда {{v0}} завершилася з кодом {{v1}}."}]}`

func catalog(t *testing.T) *Catalog {
	c, err := ParseCatalog(strings.NewReader(testCatalog))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogTranslatesExactAndPatternMessages(t *testing.T) {
	c := catalog(t)
	if got := c.Text("ru", "Not enough free space"); got != "Недостаточно свободного места" {
		t.Fatal(got)
	}
	if got := c.Text("uk", "Command mdadm exited with code {{v1}}."); got != "Команда mdadm завершилася з кодом {{v1}}." {
		t.Fatal(got)
	}
	if got := c.Text("ru", "Unknown failure"); got != "Unknown failure" {
		t.Fatal(got)
	}
	if got := c.Text("en", "Недостаточно свободного места"); got != "Not enough free space" {
		t.Fatal("legacy Russian history", got)
	}
	if c.Action("uk", "file.copy") != "Копіювати" || c.Action("de", "file.copy") != "Copy" || c.Action("ru", "file.nope") != "" {
		t.Fatal("actions")
	}
	var missing *Catalog
	if missing.Text("ru", "x") != "x" || missing.Action("ru", "file.copy") != "" {
		t.Fatal("nil catalog")
	}
}

func TestJobMessageNamesTaskObjectAndReason(t *testing.T) {
	e := Event{Kind: "job", Severity: "error", Action: "file.copy", Status: "failed", Object: "/srv/md127/photos", Detail: "Not enough free space"}
	m := e.Localized("ru", catalog(t))
	want := "Задача «Копировать» завершилась с ошибкой.\nОбъект: /srv/md127/photos\nПричина: Недостаточно свободного места"
	if m.Title != "PaNasMs · Ошибка" || m.Body != want {
		t.Fatalf("%q", m.Body)
	}
	e.Status, e.Object, e.Detail = "interrupted", "cloud:263be083/Backups/2026", ""
	if got := e.Localized("en", nil).Body; got != "Task “file.copy” was interrupted.\nObject: Cloud: /Backups/2026" {
		t.Fatalf("%q", got)
	}
	e.Resolved = true
	if got := e.Localized("uk", catalog(t)); !strings.HasPrefix(got.Body, "Усунено: Завдання «Копіювати» перервано.") || got.Title != "PaNasMs · Інформація" {
		t.Fatal(got)
	}
	legacy := Event{Kind: "job", Severity: "error", Object: "x"}
	if got := legacy.Message("ru").Body; got != "Операция требует внимания. Проверьте результат в списке задач.\nx" {
		t.Fatal("queued deliveries without details keep the old text", got)
	}
	long := Event{Kind: "job", Severity: "error", Action: "file.copy", Detail: strings.Repeat("я", 5000)}
	if n := len([]rune(long.Message("en").Body)); n > 1100 {
		t.Fatal(n)
	}
}
