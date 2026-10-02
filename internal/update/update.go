package update

import (
	"context"
	"embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed self-update.sh
var updateScript embed.FS

type Manager struct {
	currentVersion string
	httpClient     *http.Client
}

const updateAttemptTimeout = 7 * time.Minute

func NewManager(currentVersion string) *Manager {
	return &Manager{
		currentVersion: currentVersion,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (m *Manager) GetCurrentVersion() string {
	return m.currentVersion
}

// FetchLatestVersion gets the latest version as text from the /latest endpoint
func (m *Manager) FetchLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://get.wantastic.app/latest", nil)
	if err != nil {
		return "", err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch latest version: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// RunUpdateScript executes the embedded self-update.sh script
func (m *Manager) RunUpdateScript(ctx context.Context, targetVersion, binaryPath string) error {
	// The agent context normally lives for the lifetime of the process. Give the
	// external downloader its own deadline so a stalled update can never pin the
	// update worker indefinitely.
	updateCtx, cancel := context.WithTimeout(ctx, updateAttemptTimeout)
	defer cancel()

	scriptContent, err := updateScript.ReadFile("self-update.sh")
	if err != nil {
		return fmt.Errorf("read embedded script: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "self-update-*.sh")
	if err != nil {
		return fmt.Errorf("create temp script: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(scriptContent); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp script: %w", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		return fmt.Errorf("chmod temp script: %w", err)
	}

	log.Printf("Running update script for version %s (target: %s)...", targetVersion, binaryPath)
	// Pass binaryPath as second argument
	cmd := exec.CommandContext(updateCtx, "/bin/sh", tmpFile.Name(), targetVersion, binaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Run(); err != nil {
		if updateCtx.Err() != nil {
			return fmt.Errorf("update attempt timed out after %s: %w", updateAttemptTimeout, updateCtx.Err())
		}
		return fmt.Errorf("execute update script: %w", err)
	}

	return nil
}

type releaseVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease string
}

func parseReleaseVersion(raw string) (releaseVersion, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "v")
	value, _, _ = strings.Cut(value, "+")
	core, prerelease, _ := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return releaseVersion{}, fmt.Errorf("version %q is not major.minor.patch", raw)
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return releaseVersion{}, fmt.Errorf("version %q has an invalid numeric component", raw)
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return releaseVersion{}, fmt.Errorf("version %q has an invalid numeric component: %w", raw, err)
		}
		numbers[i] = number
	}
	return releaseVersion{
		major:      numbers[0],
		minor:      numbers[1],
		patch:      numbers[2],
		prerelease: prerelease,
	}, nil
}

func compareReleaseVersions(left, right releaseVersion) int {
	for _, pair := range [][2]uint64{
		{left.major, right.major},
		{left.minor, right.minor},
		{left.patch, right.patch},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if left.prerelease == right.prerelease {
		return 0
	}
	if left.prerelease == "" {
		return 1
	}
	if right.prerelease == "" {
		return -1
	}
	return comparePrerelease(left.prerelease, right.prerelease)
}

func comparePrerelease(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < len(leftParts) && i < len(rightParts); i++ {
		if leftParts[i] == rightParts[i] {
			continue
		}
		leftNumber, leftErr := strconv.ParseUint(leftParts[i], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightParts[i], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		default:
			return strings.Compare(leftParts[i], rightParts[i])
		}
	}
	if len(leftParts) < len(rightParts) {
		return -1
	}
	return 1
}

// ShouldUpdate returns true only when targetVersion is strictly newer. Build
// metadata is intentionally ignored, so a stale release channel can never
// downgrade a newer agent or restart one for a different build of the same tag.
func (m *Manager) ShouldUpdate(targetVersion string) (bool, error) {
	current, err := parseReleaseVersion(m.currentVersion)
	if err != nil {
		return false, fmt.Errorf("parse current version: %w", err)
	}
	target, err := parseReleaseVersion(targetVersion)
	if err != nil {
		return false, fmt.Errorf("parse target version: %w", err)
	}
	return compareReleaseVersions(current, target) < 0, nil
}

// CheckAndUpdate checks for updates and applies them. Returns true if updated.
func (m *Manager) CheckAndUpdate(ctx context.Context, targetVersion string) (bool, error) {
	shouldUpdate, err := m.ShouldUpdate(targetVersion)
	if err != nil {
		return false, err
	}
	if !shouldUpdate {
		log.Printf("No newer release available: current=%s offered=%s", m.currentVersion, targetVersion)
		return false, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("failed to determine executable path: %w", err)
	}

	// Resolve symlinks just in case
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}

	if err := m.RunUpdateScript(ctx, targetVersion, execPath); err != nil {
		return false, err
	}

	return true, nil
}

func (m *Manager) restart() error {
	// Get current executable path and arguments
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	args := os.Args[1:]

	// Start new process
	cmd := exec.Command(executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start new process: %w", err)
	}

	// Exit current process
	os.Exit(0)
	return nil
}

// GetPlatform returns the current OS and architecture for update URLs
func GetPlatform() string {
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// BuildUpdateURL constructs an update URL for the given version and platform
func BuildUpdateURL(version, platform string) string {
	releaseTag, _, _ := strings.Cut(strings.TrimSpace(version), "+")
	return fmt.Sprintf("https://get.wantastic.app/%s/wantasticd-%s.tar.gz", releaseTag, platform)
}
