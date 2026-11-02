package storagequery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func Redact(raw json.RawMessage) (json.RawMessage, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid storage result")
	}
	if object, ok := value.(map[string]any); ok {
		// Disk-sleep state keys contain hardware serials, even after removing
		// serial fields. Members cannot correlate those admin-only identities.
		if _, exists := object["sleepStatus"]; exists {
			object["sleepStatus"] = map[string]any{}
		}
	}
	var visit func(any)
	visit = func(value any) {
		switch object := value.(type) {
		case map[string]any:
			delete(object, "serial")
			delete(object, "wwn")
			for _, child := range object {
				visit(child)
			}
		case []any:
			for _, child := range object {
				visit(child)
			}
		}
	}
	visit(value)
	return json.Marshal(value)
}
