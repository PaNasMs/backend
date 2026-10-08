package volumeaccess

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

func TestOnlyWritableDataFilesystemRoots(t *testing.T) {
	rows := mounts(`1 0 179:2 / / rw - ext4 /dev/mmcblk0p2 rw
2 1 179:1 / /boot/firmware rw - vfat /dev/mmcblk0p1 rw
3 1 9:127 / /srv/RAID\040data rw - ext4 /dev/md127 rw
4 1 179:3 / /srv/card rw - ext4 /dev/mmcblk0p3 rw
5 1 179:2 / /mnt/system-alias rw - ext4 /dev/mmcblk0p2 rw
6 1 9:127 /private /mnt/bind rw - ext4 /dev/md127 rw
7 1 8:1 / /media/readonly ro - ext4 /dev/sda1 ro
8 1 0:45 / /mnt/remote rw - nfs4 server:/share rw
9 1 8:2 / /mnt/boot rw - ext4 /dev/sda2 rw
10 1 0:46 / /mnt/overlay rw - overlay overlay rw
11 1 8:3 / /var/lib/docker rw - ext4 /dev/sda3 rw
12 1 8:3 / /mnt/docker-alias rw - ext4 /dev/sda3 rw`)
	got := candidates(rows, map[string]bool{"8:2": true})
	if len(got) != 2 || got[0].point != "/srv/RAID data" || got[1].device != "179:3" {
		t.Fatalf("unexpected eligible volumes: %+v", got)
	}
}
func TestSystemFilesystemOnRAIDIsProtected(t *testing.T) {
	got := candidates([]mount{{device: "9:0", point: "/", root: "/", fs: "ext4", options: "rw"}, {device: "9:0", point: "/srv/raid", root: "/", fs: "ext4", options: "rw"}}, map[string]bool{})
	if len(got) != 0 {
		t.Fatal("system RAID alias accepted")
	}
}
func TestPathComponentBoundaries(t *testing.T) {
	for _, p := range []string{"/", "/boot/firmware", "/home/pasha", "/var/lib", "/usr/local", "/etc"} {
		if !systemPath(p) {
			t.Errorf("system path accepted: %s", p)
		}
	}
	for _, p := range []string{"/home-data", "/srv/home", "/media/boot"} {
		if systemPath(p) {
			t.Errorf("data path rejected: %s", p)
		}
	}
}

func TestLiveSharedVolume(t *testing.T) {
	point := os.Getenv("PANASMS_TEST_VOLUME")
	if point == "" {
		t.Skip("requires a disposable mounted test filesystem")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	before, err := exec.Command("getfacl", "-p", "/").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyMounted("/"); err != nil {
		t.Fatal(err)
	}
	after, err := exec.Command("getfacl", "-p", "/").Output()
	if err != nil || string(before) != string(after) {
		t.Fatal("system root ACL changed")
	}
	if err = ApplyMounted(point); err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroup("users")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}
	for i, script := range []string{`mkdir "$1/shared" && printf first > "$1/shared/first"`, `printf second > "$1/shared/second" && mkdir "$1/shared/nested"`} {
		cmd := exec.Command("sh", "-c", script, "test", point)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(60000 + i), Gid: uint32(60000 + i), Groups: []uint32{uint32(gid)}}}
		if out, e := cmd.CombinedOutput(); e != nil {
			details, _ := exec.Command("findmnt", "-no", "OPTIONS", "--target", point).Output()
			t.Fatalf("user %d: %v: %s; mount options: %s", i, e, out, details)
		}
	}
}
