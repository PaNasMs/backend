package webaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type State struct {
	Phase    string `json:"phase,omitempty"`
	Previous int    `json:"previous,omitempty"`
	Port     int    `json:"port,omitempty"`
	Error    string `json:"error,omitempty"`
}
type Service struct {
	Config, StatePath, Lock string
	Write                   func(string, string, os.FileMode) error
	Run                     func([]string) error
	Available               func(int) error
	Healthy                 func(int) bool
	Sleep                   func(time.Duration)
}

func Default() *Service {
	return &Service{
		Config: "/etc/panasms/web.env", StatePath: "/var/lib/panasms-agent/web-access.json", Lock: "/var/lib/panasms-agent/web-access.lock",
		Write: systemops.AtomicWrite, Run: func(args []string) error {
			_, err := systemops.Command(context.Background(), args, systemops.CommandOptions{Operation: true})
			return err
		}, Available: available, Healthy: healthy, Sleep: time.Sleep,
	}
}
func rejected(s string) error { return &systemops.Rejected{Message: s} }

var blocked = map[int]bool{}

func init() {
	for _, p := range strings.Split("1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,989,990,993,995,1719,1720,1723,2049,3659,4045,4190,5060,5061,6000,6566,6665,6666,6667,6668,6669,6679,6697,10080", ",") {
		n, _ := strconv.Atoi(p)
		blocked[n] = true
	}
}
func Port(v any) (int, error) {
	n, ok := v.(int)
	if !ok {
		number, yes := v.(json.Number)
		if !yes {
			return 0, rejected("Enter an HTTP port between 1 and 65535")
		}
		i, err := strconv.ParseInt(string(number), 10, 32)
		if err != nil {
			return 0, rejected("Enter an HTTP port between 1 and 65535")
		}
		n = int(i)
	}
	if n < 1 || n > 65535 {
		return 0, rejected("Enter an HTTP port between 1 and 65535")
	}
	if blocked[n] {
		return 0, rejected("Browsers block this HTTP port. Choose another port.")
	}
	return n, nil
}
func (s *Service) Current() (int, error) {
	raw, err := os.ReadFile(s.Config)
	if os.IsNotExist(err) {
		return 80, nil
	}
	if err != nil {
		return 0, err
	}
	v := strings.TrimPrefix(strings.TrimSpace(string(raw)), "PANASMS_HTTP_PORT=")
	if v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, rejected("Invalid HTTP port configuration")
	}
	return Port(json.Number(v))
}
func (s *Service) state() (State, error) {
	raw, err := os.ReadFile(s.StatePath)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	err = systemops.Decode(raw, &st)
	return st, err
}
func (s *Service) save(st State) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.Write(s.StatePath, string(raw), 0600)
}
func (s *Service) Query() (json.RawMessage, error) {
	st, err := s.state()
	if err != nil {
		return nil, err
	}
	p, err := s.Current()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"port": p, "pending": st.Phase == "scheduled" || st.Phase == "applying", "error": st.Error})
}
func (s *Service) validate(v any) (int, int, error) {
	p, err := Port(v)
	if err != nil {
		return 0, 0, err
	}
	st, err := s.state()
	if err != nil {
		return 0, 0, err
	}
	if st.Phase == "scheduled" || st.Phase == "applying" {
		return 0, 0, rejected("An HTTP port change is already in progress")
	}
	old, err := s.Current()
	if err != nil {
		return 0, 0, err
	}
	if p != old {
		err = s.Available(p)
	}
	return p, old, err
}
func (s *Service) Plan(action string, params map[string]any) (json.RawMessage, error) {
	p, old, err := s.validate(params["port"])
	if err != nil {
		return nil, err
	}
	fp, err := systemops.Fingerprint(action, params, json.Number(strconv.Itoa(old)))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"target": strconv.Itoa(p), "confirmation": strconv.Itoa(p), "details": []string{"The web interface will restart on the selected HTTP port"}, "fingerprint": fp})
}
func (s *Service) locked(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.Lock), 0750); err != nil {
		return err
	}
	fd, err := unix.Open(s.Lock, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}
func (s *Service) Execute(params map[string]any) (json.RawMessage, error) {
	var result json.RawMessage
	err := s.locked(func() error {
		p, old, err := s.validate(params["port"])
		if err != nil {
			return err
		}
		if p == old {
			result, _ = json.Marshal(map[string]any{"port": p})
			return nil
		}
		if err := s.save(State{Phase: "scheduled", Previous: old, Port: p}); err != nil {
			return err
		}
		if err := s.Run([]string{"systemd-run", "--collect", "--unit=panasms-web-access", "--on-active=3s", "--timer-property=AccuracySec=1s", "--timer-property=RemainAfterElapse=no", "/usr/lib/panasms/panasms-system-helper", "web-access", "--apply"}); err != nil {
			return errors.Join(err, os.Remove(s.StatePath))
		}
		result, _ = json.Marshal(map[string]any{"port": p, "message": "HTTP port change scheduled"})
		return nil
	})
	return result, err
}
func (s *Service) writePort(p int) error {
	if _, err := Port(p); err != nil {
		return err
	}
	return s.Write(s.Config, fmt.Sprintf("PANASMS_HTTP_PORT=%d\n", p), 0644)
}
func (s *Service) Apply() error {
	return s.locked(func() error {
		st, err := s.state()
		if err != nil || st.Phase != "scheduled" {
			return err
		}
		if _, err := Port(st.Previous); err != nil {
			return err
		}
		if _, err := Port(st.Port); err != nil {
			return err
		}
		apply := func() error {
			if err := s.Available(st.Port); err != nil {
				return err
			}
			st.Phase = "applying"
			if err := s.save(st); err != nil {
				return err
			}
			if err := s.writePort(st.Port); err != nil {
				return err
			}
			if err := s.Run([]string{"systemctl", "restart", "panasms-core.service"}); err != nil {
				return err
			}
			for i := 0; i < 20; i++ {
				if s.Healthy(st.Port) {
					st.Phase = "ready"
					return s.save(st)
				}
				s.Sleep(time.Second)
			}
			return rejected("The web interface did not start on the new port. The previous port was restored.")
		}
		if err := apply(); err != nil {
			if rollback := s.writePort(st.Previous); rollback != nil {
				return errors.Join(err, rollback)
			}
			st.Phase = "failed"
			st.Error = "The web interface did not start on the new port. The previous port was restored."
			saveErr := s.save(st)
			restartErr := s.Run([]string{"systemctl", "restart", "panasms-core.service"})
			return errors.Join(err, saveErr, restartErr)
		}
		return nil
	})
}
func (s *Service) Recover() error {
	return s.locked(func() error {
		st, err := s.state()
		if err != nil {
			return err
		}
		if st.Phase != "scheduled" && st.Phase != "applying" {
			return nil
		}
		if err := s.writePort(st.Previous); err != nil {
			return err
		}
		st.Phase = "failed"
		st.Error = "The interrupted HTTP port change was rolled back."
		return s.save(st)
	})
}
func (s *Service) Configure(value any) (int, error) {
	var p int
	err := s.locked(func() error {
		if value == nil {
			current, err := s.Current()
			if err != nil {
				return err
			}
			value = current
		}
		var err error
		p, _, err = s.validate(value)
		if err != nil {
			return err
		}
		if !s.Healthy(p) {
			if err := s.Available(p); err != nil {
				return err
			}
		}
		return s.writePort(p)
	})
	return p, err
}
func available(port int) error {
	var fds []int
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if errors.Is(err, unix.EAFNOSUPPORT) {
			continue
		}
		if err != nil {
			return err
		}
		fds = append(fds, fd)
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return err
		}
		var addr unix.Sockaddr = &unix.SockaddrInet4{Port: port}
		if family == unix.AF_INET6 {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
				return err
			}
			addr = &unix.SockaddrInet6{Port: port}
		}
		if err := unix.Bind(fd, addr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return rejected("The HTTP port is occupied or unavailable. Choose another port.")
		}
	}
	return nil
}
func healthy(port int) bool {
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var body struct {
		Status string `json:"status"`
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&body) == nil && body.Status == "ok"
}
