package storagequery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
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
		// State keys contain serials. These per-response handles preserve all
		// observations, including stale entries sharing a device path.
		if states, ok := object["sleepStatus"].(map[string]any); ok {
			keys := make([]string, 0, len(states))
			for key := range states {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			redacted := make(map[string]any, len(states))
			for index, key := range keys {
				redacted["state-"+strconv.Itoa(index)] = states[key]
			}
			object["sleepStatus"] = redacted
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
