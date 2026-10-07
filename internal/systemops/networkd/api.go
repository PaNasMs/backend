package networkd

import "encoding/json"

func Query(names []string) map[string]View { return query(names) }
func Lock() (func(), error)                { return lock() }
func Validate(c Config) error {
	copy := c
	if copy.IPv6.Method == "ignore" {
		copy.IPv6.Method = "disabled"
	}
	return validate(copy)
}
func Operation(mode, action, user string, params map[string]any) (any, error) {
	r := request{Action: action, User: user}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &r.Params); err != nil {
		return nil, err
	}
	if mode == "plan" {
		return plan(r)
	}
	return execute(r)
}

// SharingSource captures only the simple IP settings supported by the existing editor.
func SharingSource(name, bridge string) (string, map[string]any, string, error) {
	s, e := inspect(name)
	if e != nil {
		return "", nil, "", e
	}
	b, e := render(bridge, "", s.Text, s.Config)
	if e != nil {
		return "", nil, "", e
	}
	return b, s.Netplan, s.Fingerprint, nil
}
