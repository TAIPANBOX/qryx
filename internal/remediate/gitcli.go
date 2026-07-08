package remediate

import (
	"fmt"
	"os/exec"
	"strings"
)

// GitCLI is the production Runner: it shells out to git and gh. It holds no
// logic beyond invoking commands and wrapping their stderr — all decisions live
// in OpenPR so they stay testable.
type GitCLI struct{}

func (GitCLI) Dirty(files []string) (bool, error) {
	args := append([]string{"status", "--porcelain", "--"}, files...)
	out, err := run("git", args...)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

func (GitCLI) BaseBranch() (string, error) {
	out, err := run("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (GitCLI) CreateBranch(name string) error {
	_, err := run("git", "switch", "-c", name)
	return err
}

func (GitCLI) Add(files []string) error {
	_, err := run("git", append([]string{"add", "--"}, files...)...)
	return err
}

func (GitCLI) Commit(message string) error {
	_, err := run("git", "commit", "-m", message)
	return err
}

func (GitCLI) Push(branch string) error {
	_, err := run("git", "push", "-u", "origin", branch)
	return err
}

func (GitCLI) CreatePR(title, body, base string) (string, error) {
	out, err := run("gh", "pr", "create", "--title", title, "--body", body, "--base", base)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// run executes a command, returning stdout and wrapping any failure with the
// command and its stderr.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) // #nosec G204 -- name is always a "git"/"gh" literal from the call sites in this file, args are our own fixed subcommands
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
