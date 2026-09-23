package accounts

import (
	"context"
	"encoding/json"
	"panasms.local/backend/internal/systemops"
)

func samba(ctx context.Context, operation, target, password string) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]string{"operation": operation, "target": target, "password": password})
	raw, err := systemops.Command(ctx, []string{"/usr/bin/python3", "-B", "/usr/lib/panasms/management/account_dependencies.py"}, systemops.CommandOptions{Input: body, Operation: operation != "status"})
	if err != nil {
		return nil, err
	}
	var result struct {
		Error string `json:"error"`
	}
	if err := systemops.Decode(raw, &result); err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, reject(result.Error)
	}
	return raw, nil
}
