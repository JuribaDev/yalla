// Package dokploy contains typed orchestration helpers for Dokploy workflows.
package dokploy

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// PlannedOperation is one operation in a composite dry-run plan.
type PlannedOperation struct {
	Order         int             `json:"order"`
	OperationID   string          `json:"operation_id"`
	Input         json.RawMessage `json:"input,omitempty"`
	Postcondition string          `json:"postcondition,omitempty"`
}

// DeployComposeOptions configures compose deployment orchestration.
type DeployComposeOptions struct {
	Project     string
	Environment string
	ComposeFile string
	EnvFile     string
	Domains     []string
	GetOrCreate bool
	DryRun      bool
	Timeout     time.Duration
}

// DeployComposeResult is the structured output for deploy compose.
type DeployComposeResult struct {
	Project     json.RawMessage    `json:"project,omitempty"`
	Environment json.RawMessage    `json:"environment,omitempty"`
	Compose     json.RawMessage    `json:"compose,omitempty"`
	Domains     []json.RawMessage  `json:"domains,omitempty"`
	Status      string             `json:"deployment_status,omitempty"`
	Operations  []PlannedOperation `json:"operations"`
	DryRun      bool               `json:"dry_run,omitempty"`
}

// DeployCompose creates/updates a compose stack, deploys it, and waits.
func DeployCompose(ctx context.Context, runner Runner, opts DeployComposeOptions) (*DeployComposeResult, error) {
	if opts.Project == "" || opts.Environment == "" || opts.ComposeFile == "" {
		return nil, yerr.New(yerr.CodeInvalidInput, "deploy compose requires --project, --env, and --compose-file")
	}
	composeBytes, err := os.ReadFile(opts.ComposeFile)
	if err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "read compose file: %v", err)
	}
	env := ""
	if opts.EnvFile != "" {
		b, err := os.ReadFile(opts.EnvFile)
		if err != nil {
			return nil, yerr.Newf(yerr.CodeInvalidInput, "read env file: %v", err)
		}
		env = string(b)
	}
	services, err := composeServices(composeBytes)
	if err != nil {
		return nil, err
	}
	for _, d := range opts.Domains {
		parts := strings.Split(d, ":")
		if len(parts) != 3 {
			return nil, yerr.Newf(yerr.CodeInvalidInput, "domain %q must be host:service:port", d)
		}
		if !services[parts[1]] {
			return nil, yerr.Newf(yerr.CodeInvalidInput, "domain %q references unknown service %q", d, parts[1])
		}
	}
	ops := []PlannedOperation{
		{1, "project-create", JSONBody(map[string]string{"name": opts.Project}), "project exists"},
		{2, "environment-create", JSONBody(map[string]string{"name": opts.Environment, "projectId": "<project.id>"}), "environment exists"},
		{3, "compose-create", JSONBody(map[string]string{"name": opts.Project, "environmentId": "<environment.id>", "composeType": "docker-compose", "appName": opts.Project}), "compose exists"},
		{4, "compose-update", JSONBody(map[string]string{"composeId": "<compose.id>", "composeFile": string(composeBytes), "env": env}), "compose file saved"},
		{5, "compose-deploy", JSONBody(map[string]string{"composeId": "<compose.id>"}), "deployment triggered"},
	}
	for i, d := range opts.Domains {
		ops = append(ops, PlannedOperation{Order: 6 + i, OperationID: "domain-create", Input: JSONBody(map[string]string{"domain": d}), Postcondition: "domain binding exists"})
	}
	out := &DeployComposeResult{Operations: ops, DryRun: opts.DryRun}
	if opts.DryRun {
		return out, nil
	}
	projectBody, projectID, err := ensureProject(ctx, runner, opts.Project, opts.GetOrCreate)
	if err != nil {
		return nil, err
	}
	out.Project = projectBody
	envBody, envID, err := ensureEnvironment(ctx, runner, projectID, opts.Environment, opts.GetOrCreate)
	if err != nil {
		return nil, err
	}
	out.Environment = envBody
	composeBody, composeID, err := ensureCompose(ctx, runner, projectID, envID, opts.Project, string(composeBytes), opts.GetOrCreate)
	if err != nil {
		return nil, err
	}
	out.Compose = composeBody
	if _, err := runner.Call(ctx, "compose-update", Input{Body: JSONBody(map[string]string{"composeId": composeID, "composeFile": string(composeBytes), "env": env})}); err != nil {
		return nil, err
	}
	for _, d := range opts.Domains {
		parts := strings.Split(d, ":")
		port, _ := strconv.Atoi(parts[2])
		res, err := runner.Call(ctx, "domain-create", Input{Body: JSONBody(map[string]any{"host": parts[0], "composeId": composeID, "serviceName": parts[1], "port": port, "domainType": "compose", "https": true, "certificateType": "letsencrypt"})})
		if err != nil {
			return nil, err
		}
		out.Domains = append(out.Domains, res.Body)
	}
	if _, err := runner.Call(ctx, "compose-deploy", Input{Body: JSONBody(map[string]string{"composeId": composeID})}); err != nil {
		return nil, err
	}
	waitCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	wr, err := WaitCompose(waitCtx, runner, composeID, "done", 2*time.Second)
	if err != nil {
		return nil, err
	}
	out.Status = wr.Status
	return out, nil
}

func ensureProject(ctx context.Context, runner Runner, name string, reuse bool) (json.RawMessage, string, error) {
	if reuse {
		if body, id, _ := findProject(ctx, runner, name); id != "" {
			return body, id, nil
		}
	}
	if _, err := runner.Call(ctx, "project-create", Input{Body: JSONBody(map[string]string{"name": name, "env": ""})}); err != nil {
		return nil, "", err
	}
	body, id, err := findProject(ctx, runner, name)
	if err != nil {
		return nil, "", err
	}
	if id == "" {
		return nil, "", yerr.Newf(yerr.CodeNotFound, "created project %q was not found in project-all", name)
	}
	return body, id, nil
}

func ensureEnvironment(ctx context.Context, runner Runner, projectID, name string, reuse bool) (json.RawMessage, string, error) {
	project, _, err := findProject(ctx, runner, projectID)
	if err != nil {
		return nil, "", err
	}
	if body, id := findEnvironmentInProject(project, name); reuse && id != "" {
		return body, id, nil
	}
	if _, err := runner.Call(ctx, "environment-create", Input{Body: JSONBody(map[string]string{"name": name, "projectId": projectID})}); err != nil {
		return nil, "", err
	}
	project, _, err = findProject(ctx, runner, projectID)
	if err != nil {
		return nil, "", err
	}
	body, id := findEnvironmentInProject(project, name)
	if id == "" {
		return nil, "", yerr.Newf(yerr.CodeNotFound, "created environment %q was not found", name)
	}
	return body, id, nil
}

func ensureCompose(ctx context.Context, runner Runner, projectID, envID, name, composeFile string, reuse bool) (json.RawMessage, string, error) {
	if reuse {
		if body, id, _ := findCompose(ctx, runner, envID, name); id != "" {
			return body, id, nil
		}
	}
	if _, err := runner.Call(ctx, "compose-create", Input{Body: JSONBody(map[string]any{"name": name, "environmentId": envID, "composeType": "docker-compose", "composeFile": composeFile, "appName": name})}); err != nil {
		return nil, "", err
	}
	body, id, err := findCompose(ctx, runner, envID, name)
	if err != nil {
		return nil, "", err
	}
	if id == "" {
		return nil, "", yerr.Newf(yerr.CodeNotFound, "created compose %q was not found", name)
	}
	_ = projectID
	return body, id, nil
}

func composeServices(b []byte) (map[string]bool, error) {
	var doc struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "parse compose YAML: %v", err)
	}
	if len(doc.Services) == 0 {
		return nil, yerr.New(yerr.CodeInvalidInput, "compose file declares no services")
	}
	out := map[string]bool{}
	for k := range doc.Services {
		out[k] = true
	}
	return out, nil
}
