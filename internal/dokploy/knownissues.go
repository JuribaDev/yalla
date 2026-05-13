package dokploy

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

//go:embed known_issues.yaml
var knownIssuesYAML string

// KnownIssue describes a known upstream Dokploy failure signature.
type KnownIssue struct {
	ID             string `json:"id"`
	OperationID    string `json:"operation_id"`
	Status         int    `json:"status"`
	Classification string `json:"classification"`
	UpstreamIssue  string `json:"upstream_issue,omitempty"`
	Workaround     string `json:"workaround,omitempty"`
}

// MatchKnownIssue converts a matching upstream failure to E_UPSTREAM_BUG.
func MatchKnownIssue(operationID string, status int, body []byte) *yerr.Error {
	if operationID == "compose-stop" && status == 500 && bytes.Contains(body, []byte("spawn /bin/sh ENOENT")) {
		msg := "Dokploy compose-stop hit known upstream shell spawn bug"
		return yerr.New(yerr.CodeUpstreamBug, msg).
			WithHint("fallback: run docker-compose-down for the appName, then retry the lifecycle operation")
	}
	return nil
}

// KnownIssuesYAML returns the embedded issue signature data.
func KnownIssuesYAML() string { return strings.TrimSpace(knownIssuesYAML) }

// FormatKnownIssueHint formats an issue reference and workaround.
func FormatKnownIssueHint(issue KnownIssue) string {
	if issue.Workaround == "" {
		return issue.UpstreamIssue
	}
	if issue.UpstreamIssue == "" {
		return issue.Workaround
	}
	return fmt.Sprintf("%s; workaround: %s", issue.UpstreamIssue, issue.Workaround)
}
