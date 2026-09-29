package notify

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	Enabled  bool   `json:"enabled"`
}
type Config struct {
	SMTP            SMTP   `json:"smtp"`
	TelegramToken   string `json:"telegramToken,omitempty"`
	TelegramEnabled bool   `json:"telegramEnabled"`
	PublicKey       string `json:"publicKey"`
	PrivateKey      string `json:"privateKey,omitempty"`
	Contact         string `json:"contact"`
}
type Preferences struct {
	Enabled bool                `json:"enabled"`
	Email   string              `json:"email"`
	ChatID  string              `json:"chatId"`
	Routes  map[string]Channels `json:"routes"`
}

func Defaults() Preferences {
	return Preferences{Routes: map[string]Channels{"info": {}, "warning": {"push"}, "error": {"email"}, "critical": {"telegram"}}}
}
func (p Preferences) Validate() error {
	if p.Email != "" {
		a, e := mail.ParseAddress(p.Email)
		if e != nil || a.Address != p.Email || strings.ContainsAny(p.Email, "\r\n") {
			return errors.New("delivery.invalidEmail")
		}
	}
	if p.ChatID != "" && !regexp.MustCompile(`^[1-9][0-9]{0,19}$`).MatchString(p.ChatID) {
		return errors.New("delivery.invalidChat")
	}
	if len(p.Routes) != 4 {
		return errors.New("delivery.invalidRoutes")
	}
	for _, level := range []string{"info", "warning", "error", "critical"} {
		channels, ok := p.Routes[level]
		if !ok {
			return errors.New("delivery.invalidRoutes")
		}
		seen := map[string]bool{}
		for _, channel := range channels {
			if (channel != "push" && channel != "email" && channel != "telegram") || seen[channel] {
				return errors.New("delivery.invalidRoutes")
			}
			seen[channel] = true
		}
	}
	return nil
}
func (c Config) Validate() error {
	if c.SMTP.Enabled {
		if c.SMTP.Host == "" || strings.ContainsAny(c.SMTP.Host, " /\r\n\x00") || c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			return errors.New("delivery.invalidSMTP")
		}
		if c.SMTP.Security != "tls" && c.SMTP.Security != "starttls" {
			return errors.New("delivery.invalidSMTP")
		}
		if a, e := mail.ParseAddress(c.SMTP.From); e != nil || a.Address != c.SMTP.From || strings.ContainsAny(c.SMTP.From, "\r\n") {
			return errors.New("delivery.invalidEmail")
		}
	}
	if len(c.SMTP.Password) > 4096 || len(c.SMTP.Username) > 256 || len(c.SMTP.Host) > 253 {
		return errors.New("delivery.invalidSMTP")
	}
	if c.TelegramEnabled && !regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,128}$`).MatchString(c.TelegramToken) {
		return errors.New("delivery.invalidToken")
	}
	if c.Contact != "" {
		a, e := mail.ParseAddress(c.Contact)
		if e != nil || a.Address != c.Contact {
			return errors.New("delivery.invalidEmail")
		}
	}
	return nil
}

type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

func (s Subscription) Validate() error {
	u, e := url.Parse(s.Endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || len(s.Endpoint) > 4096 || (u.Port() != "" && u.Port() != "443") {
		return errors.New("delivery.invalidSubscription")
	}
	h := u.Hostname()
	if h == "" || net.ParseIP(h) != nil || (!strings.HasSuffix(h, ".push.services.mozilla.com") && h != "updates.push.services.mozilla.com" && h != "fcm.googleapis.com" && h != "web.push.apple.com" && !strings.HasSuffix(h, ".notify.windows.com")) {
		return errors.New("delivery.invalidSubscription")
	}
	p, e := base64.RawURLEncoding.DecodeString(s.Keys.P256dh)
	a, e2 := base64.RawURLEncoding.DecodeString(s.Keys.Auth)
	if e != nil || e2 != nil || len(p) != 65 || p[0] != 4 || len(a) != 16 {
		return errors.New("delivery.invalidSubscription")
	}
	return nil
}

type Event struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Object   string `json:"object"`
	Route    string `json:"route"`
	Resolved bool   `json:"resolved"`
}
type Message struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
	Tag   string `json:"tag"`
}

func (e Event) Message(lang string) Message {
	i := 0
	if lang == "ru" {
		i = 1
	}
	if lang == "uk" {
		i = 2
	}
	levels := map[string][3]string{"info": {"Information", "Информация", "Інформація"}, "warning": {"Warning", "Предупреждение", "Попередження"}, "error": {"Error", "Ошибка", "Помилка"}, "critical": {"Critical", "Критическое событие", "Критична подія"}}
	texts := map[string][3]string{
		"cpu-hot":             {"CPU temperature is at least 80 °C.", "Температура процессора достигла 80 °C.", "Температура процесора досягла 80 °C."},
		"system-full":         {"Less than 5% free space remains on the system drive.", "На системном диске осталось менее 5% свободного места.", "На системному диску залишилося менше 5% вільного місця."},
		"cooling-stale":       {"Cooling telemetry is unavailable or out of date.", "Данные об охлаждении недоступны или устарели.", "Дані про охолодження недоступні або застаріли."},
		"smart":               {"The drive has a SMART warning. Check its health in Storage.", "SMART сообщает о проблеме накопителя. Проверьте его состояние в хранилище.", "SMART повідомляє про проблему накопичувача. Перевірте його стан у сховищі."},
		"heat":                {"Disk temperature is at least 50 °C.", "Температура диска достигла 50 °C.", "Температура диска досягла 50 °C."},
		"job":                 {"An operation needs attention. Review its result in Tasks.", "Операция требует внимания. Проверьте результат в списке задач.", "Операція потребує уваги. Перевірте результат у списку завдань."},
		"device-connected":    {"A drive was connected.", "Подключён накопитель.", "Підключено накопичувач."},
		"device-disconnected": {"A drive was disconnected.", "Накопитель отключён.", "Накопичувач відключено."},
		"device-busy":         {"A drive with mounted volumes or array members was disconnected. Check Storage.", "Отключён накопитель с подключёнными томами или участниками массива. Проверьте хранилище.", "Відключено накопичувач із підключеними томами або учасниками масиву. Перевірте сховище."},
		"device-ejected":      {"The drive can be disconnected safely.", "Накопитель можно безопасно отключить.", "Накопичувач можна безпечно відключити."},
		"update":              {"System update status changed. Review Updates.", "Изменилось состояние обновления системы. Проверьте раздел обновлений.", "Змінився стан оновлення системи. Перевірте розділ оновлень."},
		"test":                {"Notification delivery works.", "Доставка уведомлений работает.", "Доставка сповіщень працює."},
		"generic":             {"A new event is available in the NAS notification list.", "В списке уведомлений NAS появилось новое событие.", "У списку сповіщень NAS з’явилася нова подія."},
	}
	t, ok := texts[e.Kind]
	if !ok {
		t = texts["generic"]
	}
	body := t[i]
	if e.Resolved {
		body = [3]string{"Resolved: ", "Устранено: ", "Усунено: "}[i] + body
	}
	if e.Object != "" {
		body += "\n" + e.Object
	}
	severity := e.Severity
	if e.Resolved {
		severity = "info"
	}
	return Message{Title: "PaNasMs · " + levels[severity][i], Body: body, URL: e.Route, Tag: e.ID}
}

// Read legacy single-channel preferences without changing their delivery behavior.
type Channels []string

func (c *Channels) UnmarshalJSON(raw []byte) error {
	var legacy string
	if err := json.Unmarshal(raw, &legacy); err == nil {
		*c = Channels{}
		if legacy != "panel" && legacy != "" {
			*c = Channels{legacy}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	*c = Channels(list)
	return nil
}
func (c Channels) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(c))
}
