package provenance

import (
	"fmt"
	"os"
	"runtime"
)

// CIEnvironment holds detected CI build context.
type CIEnvironment struct {
	Platform     string
	Repository   string
	Commit       string
	Ref          string
	RunID        string
	RunURL       string
	Workflow     string
	BuilderID    string
	RunnerOS     string
	RunnerArch   string
}

// CIDetector detects CI environment variables.
type CIDetector interface {
	Detect() (*CIEnvironment, bool)
}

// DetectCI tries all known detectors and returns the first match.
func DetectCI() (*CIEnvironment, error) {
	detectors := []CIDetector{
		&GitHubActionsDetector{},
	}

	for _, d := range detectors {
		if env, ok := d.Detect(); ok {
			return env, nil
		}
	}

	return nil, fmt.Errorf("no CI environment detected; use --repo and --commit flags for manual provenance")
}

// GitHubActionsDetector detects GitHub Actions environment.
type GitHubActionsDetector struct{}

func (d *GitHubActionsDetector) Detect() (*CIEnvironment, bool) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil, false
	}

	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	serverURL := os.Getenv("GITHUB_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://github.com"
	}

	runURL := ""
	if repo != "" && runID != "" {
		runURL = fmt.Sprintf("%s/%s/actions/runs/%s", serverURL, repo, runID)
	}

	return &CIEnvironment{
		Platform:   "github-actions",
		Repository: fmt.Sprintf("%s/%s", serverURL, repo),
		Commit:     os.Getenv("GITHUB_SHA"),
		Ref:        os.Getenv("GITHUB_REF"),
		RunID:      runID,
		RunURL:     runURL,
		Workflow:   os.Getenv("GITHUB_WORKFLOW"),
		BuilderID:  fmt.Sprintf("%s/%s/actions/runs/%s", serverURL, repo, runID),
		RunnerOS:   getEnvOrDefault("RUNNER_OS", runtime.GOOS),
		RunnerArch: getEnvOrDefault("RUNNER_ARCH", runtime.GOARCH),
	}, true
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
