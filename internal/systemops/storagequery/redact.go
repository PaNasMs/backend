package storagequery

import "encoding/json"

func Redact(raw json.RawMessage) (json.RawMessage, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
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
