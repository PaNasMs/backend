package folders

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
)

type LiveMount struct {
	ID                                            uint64
	Device, Root, Target, Options, FSType, Source string
}

func UnescapeMount(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}
func ParseMounts(data string) ([]LiveMount, error) {
	rows := []LiveMount{}
	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		halves := strings.SplitN(line, " - ", 2)
		if len(halves) != 2 {
			return nil, fmt.Errorf("invalid mount inventory")
		}
		a, b := strings.Fields(halves[0]), strings.Fields(halves[1])
		if len(a) < 6 || len(b) < 3 {
			return nil, fmt.Errorf("invalid mount inventory")
		}
		id, err := strconv.ParseUint(a[0], 10, 64)
		if err != nil {
			return nil, err
		}
		rows = append(rows, LiveMount{ID: id, Device: a[2], Root: UnescapeMount(a[3]), Target: UnescapeMount(a[4]), Options: a[5], FSType: b[0], Source: UnescapeMount(b[1])})
	}
	return rows, nil
}
func ReadMounts() ([]LiveMount, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return ParseMounts(string(raw))
}
func DirectoryMount(file *os.File, rows []LiveMount) (LiveMount, error) {
	var st unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil {
		return LiveMount{}, err
	}
	for _, row := range rows {
		if row.ID == st.Mnt_id {
			return row, nil
		}
	}
	return LiveMount{}, reject("The destination volume is unavailable")
}
