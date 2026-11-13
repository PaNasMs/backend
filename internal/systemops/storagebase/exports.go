package storagebase

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

var exportEscape = regexp.MustCompile(`\\([0-7]{3})`)

func ParseExports(raw []byte) []string {
	paths := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		paths = append(paths, exportEscape.ReplaceAllStringFunc(fields[0], func(s string) string { n, _ := strconv.ParseUint(s[1:], 8, 8); return string(rune(n)) }))
	}
	return paths
}
func ActiveNFSExports() ([]string, error) {
	raw, err := os.ReadFile("/var/lib/nfs/etab")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return ParseExports(raw), nil
}
