package modulelifecycle

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

type versionCompare func(context.Context, string, string, string) (bool, error)

func compareDebian(ctx context.Context, left, operator, right string) (bool, error) {
	if operator != "gt" && operator != "ge" {
		return false, reject("Invalid OS package version comparison")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg", "--compare-versions", left, operator, right)
	cmd.Env = []string{"LC_ALL=C"}
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) && exited.ExitCode() == 1 {
		return false, nil
	}
	return false, reject("Could not compare OS package versions")
}

var aptCandidate = regexp.MustCompile(`(?m)^\s*Candidate:\s+(\S+)`)

func packagePlan(ctx context.Context, manifests []Manifest, run command, compare versionCompare) ([]string, []string, error) {
	required := map[string]string{}
	for _, manifest := range manifests {
		packages, valid := object(manifest, "packages")
		if !valid || len(packages) > 64 {
			return nil, nil, reject("Invalid system dependencies")
		}
		for _, name := range names(packages) {
			minimum, valid := packages[name].(string)
			if !packagePattern.MatchString(name) || !valid || !packageVersionPattern.MatchString(minimum) {
				return nil, nil, reject("Invalid system dependency")
			}
			old, found := required[name]
			if !found {
				required[name] = minimum
				continue
			}
			greater, err := compare(ctx, minimum, "gt", old)
			if err != nil {
				return nil, nil, err
			}
			if greater {
				required[name] = minimum
			}
		}
	}
	missing, changes := []string{}, []string{}
	for _, name := range names(required) {
		minimum := required[name]
		found, err := run(ctx, []string{"dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", name}, systemops.CommandOptions{Accepted: []int{0, 1}, Timeout: 10 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(string(found))
		if len(fields) == 2 && fields[0] == "installed" {
			adequate, err := compare(ctx, fields[1], "ge", minimum)
			if err != nil {
				return nil, nil, err
			}
			if adequate {
				continue
			}
		}
		policy, err := run(ctx, []string{"apt-cache", "policy", name}, systemops.CommandOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		match := aptCandidate.FindStringSubmatch(string(policy))
		adequate := false
		if match != nil && match[1] != "(none)" && packageVersionPattern.MatchString(match[1]) {
			adequate, err = compare(ctx, match[1], "ge", minimum)
			if err != nil {
				return nil, nil, err
			}
		}
		if !adequate {
			return nil, nil, reject("OS repositories have no suitable package " + name + " >= " + minimum + ". Refresh OS package lists.")
		}
		missing = append(missing, name+"="+match[1])
	}
	if len(missing) > 0 {
		argv := append([]string{"apt-get", "--simulate", "--no-remove", "install"}, missing...)
		output, err := run(ctx, argv, systemops.CommandOptions{Timeout: 60 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "Remv" {
				return nil, nil, reject("Dependencies require removing system packages")
			}
			if strings.HasPrefix(line, "Inst ") {
				changes = append(changes, line)
			}
		}
	}
	return missing, changes, nil
}
