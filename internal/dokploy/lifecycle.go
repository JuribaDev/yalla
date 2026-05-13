package dokploy

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// TeardownOptions configures project teardown orchestration.
type TeardownOptions struct {
	Project   string
	NoCascade bool
	DryRun    bool
	Timeout   time.Duration
}

// TeardownResult is the structured output for teardown project.
type TeardownResult struct {
	Project    string             `json:"project"`
	Operations []PlannedOperation `json:"operations"`
	Orphans    json.RawMessage    `json:"orphans,omitempty"`
	DryRun     bool               `json:"dry_run,omitempty"`
}

// TeardownProject removes a project and asserts no orphan containers remain.
func TeardownProject(ctx context.Context, runner Runner, opts TeardownOptions) (*TeardownResult, error) {
	if opts.Project == "" {
		return nil, yerr.New(yerr.CodeInvalidInput, "teardown project requires --project")
	}
	ops := []PlannedOperation{{1, "project-remove", JSONBody(map[string]string{"projectId": opts.Project}), "project removed"}}
	if !opts.NoCascade {
		ops = []PlannedOperation{
			{1, "project-one/project-all", JSONBody(map[string]string{"project": opts.Project}), "project resolved"},
			{2, "environment-byProjectId", JSONBody(map[string]string{"projectId": opts.Project}), "environments enumerated"},
			{3, "compose-stop", nil, "composes stopped"},
			{4, "compose-delete", nil, "composes deleted"},
			{5, "environment-remove", nil, "environments removed"},
			{6, "project-remove", JSONBody(map[string]string{"projectId": opts.Project}), "project removed"},
			{7, "docker-getContainersByAppNameMatch", JSONBody(map[string]string{"appName": opts.Project}), "no orphan containers"},
		}
	}
	out := &TeardownResult{Project: opts.Project, Operations: ops, DryRun: opts.DryRun}
	if opts.DryRun {
		return out, nil
	}
	if opts.NoCascade {
		_, err := runner.Call(ctx, "project-remove", Input{Body: JSONBody(map[string]string{"projectId": opts.Project})})
		return out, err
	}
	project, projectID, err := findProject(ctx, runner, opts.Project)
	if err != nil {
		return out, err
	}
	if projectID == "" {
		return out, yerr.Newf(yerr.CodeNotFound, "project %q not found", opts.Project)
	}
	appNames := []string{opts.Project}
	var projectObj map[string]json.RawMessage
	_ = json.Unmarshal(project, &projectObj)
	for _, env := range recordsFrom(projectObj["environments"]) {
		var envObj map[string]json.RawMessage
		_ = json.Unmarshal(env, &envObj)
		envID := firstStringField(env, "environmentId", "id")
		for _, compose := range recordsFrom(envObj["compose"]) {
			composeID := firstStringField(compose, "composeId", "id")
			appName := firstStringField(compose, "appName", "name")
			if appName != "" {
				appNames = append(appNames, appName)
			}
			if composeID != "" {
				if _, err := runner.Call(ctx, "compose-stop", Input{Body: JSONBody(map[string]string{"composeId": composeID})}); err != nil {
					var ye *yerr.Error
					if ok := errors.As(err, &ye); ok && ye.Code == yerr.CodeUpstreamBug && appName != "" {
						_, _ = runner.Call(ctx, "docker-compose-down", Input{Body: JSONBody(map[string]string{"appName": appName})})
					}
				}
				_, _ = runner.Call(ctx, "compose-delete", Input{Body: JSONBody(map[string]string{"composeId": composeID})})
			}
		}
		if envID != "" {
			_, _ = runner.Call(ctx, "environment-remove", Input{Body: JSONBody(map[string]string{"environmentId": envID})})
		}
	}
	if _, err := runner.Call(ctx, "project-remove", Input{Body: JSONBody(map[string]string{"projectId": projectID})}); err != nil {
		return out, err
	}
	for _, appName := range appNames {
		orphans, err := runner.Call(ctx, "docker-getContainersByAppNameMatch", Input{Query: map[string][]string{"appName": {appName}}})
		if err != nil {
			return out, err
		}
		if countRecords(orphans.Body) > 0 {
			out.Orphans = orphans.Body
			return out, yerr.Newf(yerr.CodeOrphan, "orphan containers remain for appName %q", appName).
				WithHint("run `yalla rescue orphans --app-name " + appName + "`")
		}
	}
	return out, nil
}
