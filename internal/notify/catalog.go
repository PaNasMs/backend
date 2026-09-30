package notify

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Catalog holds the web interface translations that notifications reuse:
// operation names and localized server messages. The frontend build emits it
// as notification-catalog.json next to the SPA assets.
type Catalog struct {
	actions  map[string]map[string]string
	exact    map[string]map[string]string
	patterns []catalogPattern
}
type catalogPattern struct {
	pattern      *regexp.Regexp
	variables    []string
	translations map[string]string
}

var placeholder = regexp.MustCompile(`\{\{(v\d+)\}\}`)

func LoadCatalog(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseCatalog(io.LimitReader(f, 8<<20))
}

func ParseCatalog(r io.Reader) (*Catalog, error) {
	var raw struct {
		Actions  map[string]map[string]string `json:"actions"`
		Messages []struct {
			Source []string `json:"source"`
			En     string   `json:"en"`
			Ru     string   `json:"ru"`
			Uk     string   `json:"uk"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	c := &Catalog{actions: raw.Actions, exact: map[string]map[string]string{}}
	for _, message := range raw.Messages {
		m := map[string]string{"en": message.En, "ru": message.Ru, "uk": message.Uk}
		// Sources are the English server text and Russian text in history written before localization.
		for _, source := range message.Source {
			if source == "" {
				continue
			}
			variables := []string{}
			for _, match := range placeholder.FindAllStringSubmatch(source, -1) {
				variables = append(variables, match[1])
			}
			if len(variables) == 0 {
				c.exact[source] = m
				continue
			}
			chunks := placeholder.Split(source, -1)
			if strings.TrimSpace(strings.Join(chunks, "")) == "" {
				continue
			}
			for i, chunk := range chunks {
				chunks[i] = regexp.QuoteMeta(chunk)
			}
			expression, err := regexp.Compile(`^(?s)` + strings.Join(chunks, `(.*?)`) + `$`)
			if err != nil {
				continue
			}
			c.patterns = append(c.patterns, catalogPattern{expression, variables, m})
		}
	}
	// Prefer the most specific pattern, as the web interface does.
	sort.SliceStable(c.patterns, func(i, j int) bool {
		return len(c.patterns[i].pattern.String()) > len(c.patterns[j].pattern.String())
	})
	return c, nil
}

// Action returns the localized operation name, or "" when it is unknown.
func (c *Catalog) Action(lang, action string) string {
	if c == nil {
		return ""
	}
	names := c.actions[action]
	if names[lang] != "" {
		return names[lang]
	}
	return names["en"]
}

// Text localizes a server message; unknown text is returned unchanged.
func (c *Catalog) Text(lang, text string) string {
	if c == nil || len(text) > 8192 {
		return text
	}
	if m, ok := c.exact[text]; ok {
		return pick(m, lang, text)
	}
	for _, p := range c.patterns {
		match := p.pattern.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		values := map[string]string{}
		for i, name := range p.variables {
			values[name] = match[i+1]
		}
		return placeholder.ReplaceAllStringFunc(pick(p.translations, lang, text), func(token string) string {
			return values[placeholder.FindStringSubmatch(token)[1]]
		})
	}
	return text
}

func pick(m map[string]string, lang, fallback string) string {
	if m[lang] != "" {
		return m[lang]
	}
	if m["en"] != "" {
		return m["en"]
	}
	return fallback
}
