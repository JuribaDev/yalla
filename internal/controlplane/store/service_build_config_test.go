package store

import (
	"encoding/json"
	"testing"
)

func TestServiceBuildConfigValidation(t *testing.T) {
	_, err := validateServiceBuildConfigInput("org_0123456789abcdefghjkmnpqrs", "svc_0123456789abcdefghjkmnpqrs", ServiceBuildConfigInput{
		BuildType:  BuildTypeDockerfile,
		SourceType: "git",
		SourceJSON: json.RawMessage(`{"repo":"https://github.com/example/api"}`),
		ConfigJSON: json.RawMessage(`{"context":".","dockerfile":"Dockerfile"}`),
	})
	if err != nil {
		t.Fatalf("validate dockerfile build config: %v", err)
	}
}

func TestServiceBuildConfigRejectsRawSecrets(t *testing.T) {
	_, err := validateServiceBuildConfigInput("org_0123456789abcdefghjkmnpqrs", "svc_0123456789abcdefghjkmnpqrs", ServiceBuildConfigInput{
		BuildType:  BuildTypeImage,
		SourceType: "image",
		SourceJSON: json.RawMessage(`{"image":"ghcr.io/example/api:latest"}`),
		ConfigJSON: json.RawMessage(`{"registry_password":"secret"}`),
	})
	if err == nil {
		t.Fatal("expected raw secret validation error")
	}
}
