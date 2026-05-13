// Package dokploy contains typed orchestration helpers for Dokploy workflows.
package dokploy

import (
	"context"
	"encoding/json"
)

func findProject(ctx context.Context, runner Runner, nameOrID string) (json.RawMessage, string, error) {
	res, err := runner.Call(ctx, "project-all", Input{})
	if err != nil {
		return nil, "", err
	}
	for _, rec := range recordsFrom(res.Body) {
		id := firstStringField(rec, "projectId", "id")
		name := firstStringField(rec, "name")
		if name == nameOrID || id == nameOrID {
			return rec, id, nil
		}
	}
	return nil, "", nil
}

func findEnvironmentInProject(project json.RawMessage, name string) (json.RawMessage, string) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(project, &obj); err != nil {
		return nil, ""
	}
	for _, rec := range recordsFrom(obj["environments"]) {
		id := firstStringField(rec, "environmentId", "id")
		if firstStringField(rec, "name") == name || id == name {
			return rec, id
		}
	}
	return nil, ""
}

func findCompose(ctx context.Context, runner Runner, envID, name string) (json.RawMessage, string, error) {
	res, err := runner.Call(ctx, "compose-search", Input{Query: map[string][]string{"environmentId": {envID}, "name": {name}}})
	if err != nil {
		return nil, "", err
	}
	for _, rec := range recordsFrom(res.Body) {
		id := firstStringField(rec, "composeId", "id")
		if firstStringField(rec, "name") == name || firstStringField(rec, "appName") == name {
			return rec, id, nil
		}
	}
	return nil, "", nil
}

func recordsFrom(raw json.RawMessage) []json.RawMessage {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	for _, key := range []string{"data", "items", "results", "projects", "environments", "compose", "composes", "containers"} {
		if err := json.Unmarshal(obj[key], &arr); err == nil {
			return arr
		}
	}
	if len(obj) > 0 {
		return []json.RawMessage{raw}
	}
	return nil
}
