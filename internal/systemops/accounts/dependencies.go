package accounts

import (
	"context"
	"encoding/json"
)

func samba(ctx context.Context, operation, target, password string) (json.RawMessage, error) {
	return defaultSharing().dependency(ctx, operation, target, password)
}
