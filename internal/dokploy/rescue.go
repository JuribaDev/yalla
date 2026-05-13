package dokploy

import (
	"context"
	"fmt"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// RescueOptions configures orphan cleanup.
type RescueOptions struct {
	AppName    string
	SSH        string
	ExecuteSSH bool
}

// RescueResult is the structured output for rescue orphans.
type RescueResult struct {
	AppName string `json:"app_name"`
	Count   int    `json:"count"`
	Command string `json:"command,omitempty"`
	UsedAPI bool   `json:"used_api,omitempty"`
}

// RescueOrphans runs API cleanup or returns an explicit fallback command.
func RescueOrphans(ctx context.Context, runner Runner, opts RescueOptions) (*RescueResult, error) {
	if opts.AppName == "" {
		return nil, yerr.New(yerr.CodeInvalidInput, "rescue orphans requires --app-name")
	}
	if _, err := runner.Call(ctx, "docker-compose-down", Input{Body: JSONBody(map[string]string{"appName": opts.AppName})}); err != nil {
		cmd := fmt.Sprintf("ssh %s 'docker ps -aq --filter name=%s | xargs -r docker rm -f'", opts.SSH, opts.AppName)
		if opts.SSH == "" {
			cmd = fmt.Sprintf("docker ps -aq --filter name=%s | xargs -r docker rm -f", opts.AppName)
			return &RescueResult{AppName: opts.AppName, Command: cmd}, yerr.New(yerr.CodeUnsupported, "docker-compose-down API operation is unavailable or failed").WithHint(cmd)
		}
		if !opts.ExecuteSSH {
			return &RescueResult{AppName: opts.AppName, Command: cmd}, nil
		}
		return &RescueResult{AppName: opts.AppName, Command: cmd}, yerr.New(yerr.CodeUnsupported, "ssh execution is not implemented by this build").WithHint(cmd)
	}
	res, err := runner.Call(ctx, "docker-getContainersByAppNameMatch", Input{Query: map[string][]string{"appName": {opts.AppName}}})
	if err != nil {
		return nil, err
	}
	return &RescueResult{AppName: opts.AppName, Count: countRecords(res.Body), UsedAPI: true}, nil
}
