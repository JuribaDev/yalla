package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var systemdUnitPaths = []string{
	"deploy/systemd/yalla-api.service",
	"deploy/systemd/yalla-worker.service",
}

func TestSystemdArtifactDefinesAPIAndWorkerUnits(t *testing.T) {
	root := projectRoot(t)
	api := parseSystemdUnit(t, filepath.Join(root, "deploy/systemd/yalla-api.service"))
	worker := parseSystemdUnit(t, filepath.Join(root, "deploy/systemd/yalla-worker.service"))

	assertSystemdSectionValue(t, api, "Unit", "Description", "Yalla Control Plane API")
	assertSystemdServiceValue(t, api, "ExecStart", "/usr/local/bin/yalla-api")
	assertSystemdServiceValue(t, api, "SyslogIdentifier", "yalla-api")
	assertSystemdSectionValue(t, worker, "Unit", "Description", "Yalla Control Plane Provisioning Worker")
	assertSystemdServiceValue(t, worker, "ExecStart", "/usr/local/bin/yalla-worker")
	assertSystemdServiceValue(t, worker, "SyslogIdentifier", "yalla-worker")

	for name, unit := range map[string]systemdUnit{"yalla-api": api, "yalla-worker": worker} {
		assertSystemdServiceValue(t, unit, "User", "yalla")
		assertSystemdServiceValue(t, unit, "Group", "yalla")
		assertSystemdServiceValue(t, unit, "WorkingDirectory", "/var/lib/yalla")
		assertSystemdServiceValue(t, unit, "EnvironmentFile", "/etc/yalla/control-plane.env")
		assertSystemdServiceValue(t, unit, "Restart", "on-failure")
		assertSystemdServiceValue(t, unit, "KillSignal", "SIGTERM")
		assertSystemdServiceValue(t, unit, "StandardOutput", "journal")
		assertSystemdServiceValue(t, unit, "StandardError", "journal")
		assertSystemdServiceValue(t, unit, "StateDirectory", "yalla")
		assertSystemdServiceValue(t, unit, "RuntimeDirectory", "yalla")
		if got := unit.sections["Install"]["WantedBy"]; got != "multi-user.target" {
			t.Fatalf("%s [Install].WantedBy = %q, want multi-user.target", name, got)
		}
	}
}

func TestSystemdArtifactKeepsSecretsRuntimeOnly(t *testing.T) {
	root := projectRoot(t)
	for _, rel := range systemdUnitPaths {
		unit := parseSystemdUnit(t, filepath.Join(root, rel))
		for key, value := range unit.sections["Service"] {
			if key == "EnvironmentFile" {
				if value != "/etc/yalla/control-plane.env" {
					t.Fatalf("%s EnvironmentFile = %q, want /etc/yalla/control-plane.env", rel, value)
				}
				continue
			}
			if key != "Environment" {
				continue
			}
			for _, assignment := range strings.Fields(value) {
				envKey, envValue, ok := strings.Cut(assignment, "=")
				if !ok {
					continue
				}
				if isSecretShapedEnvName(envKey) {
					t.Fatalf("%s bakes secret-shaped %s in Environment=; use EnvironmentFile instead", rel, envKey)
				}
				if looksLikeRenderedSecret(envValue) {
					t.Fatalf("%s Environment=%s contains a rendered secret-looking value", rel, envKey)
				}
			}
		}
	}

	envExamplePath := filepath.Join(root, "deploy/systemd/control-plane.env.example")
	envExample, err := os.ReadFile(envExamplePath)
	if err != nil {
		t.Fatalf("read deploy/systemd/control-plane.env.example: %v", err)
	}
	body := string(envExample)
	for _, want := range []string{
		"YALLA_DATABASE_URL=<redacted:postgres-dsn>",
		"YALLA_SIGNING_KEYS=<redacted:signing-keys>",
		"YALLA_SECRET_KEYS=<redacted:secret-keys>",
		"YALLA_DOKPLOY_TOKEN=<redacted:dokploy-token>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("deploy/systemd/control-plane.env.example missing redacted placeholder %q", want)
		}
	}
	if strings.Contains(body, "postgres://") || strings.Contains(body, "Bearer ") {
		t.Fatalf("deploy/systemd/control-plane.env.example must not contain rendered DSNs or bearer tokens")
	}
}

func TestSystemdArtifactPinsLeastPrivilegeSandbox(t *testing.T) {
	root := projectRoot(t)
	for _, rel := range systemdUnitPaths {
		unit := parseSystemdUnit(t, filepath.Join(root, rel))
		for key, want := range map[string]string{
			"NoNewPrivileges":         "true",
			"PrivateTmp":              "true",
			"PrivateDevices":          "true",
			"ProtectSystem":           "strict",
			"ProtectHome":             "true",
			"ProtectClock":            "true",
			"ProtectControlGroups":    "true",
			"ProtectKernelLogs":       "true",
			"ProtectKernelModules":    "true",
			"ProtectKernelTunables":   "true",
			"RestrictSUIDSGID":        "true",
			"LockPersonality":         "true",
			"MemoryDenyWriteExecute":  "true",
			"CapabilityBoundingSet":   "",
			"AmbientCapabilities":     "",
			"RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
			"SystemCallArchitectures": "native",
			"ReadWritePaths":          "/var/lib/yalla /run/yalla",
			"UMask":                   "0077",
		} {
			assertSystemdServiceValue(t, unit, key, want)
		}
	}
}

func TestSystemdArtifactDocumentsVerificationHealthAndLogs(t *testing.T) {
	root := projectRoot(t)
	readmePath := filepath.Join(root, "deploy/systemd/README.md")
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read deploy/systemd/README.md: %v", err)
	}
	readme := string(b)
	for _, want := range []string{
		"systemd-analyze verify deploy/systemd/yalla-api.service deploy/systemd/yalla-worker.service",
		"go test ./internal/release/... -run TestSystemdArtifact",
		"/usr/local/bin/yalla-api",
		"/usr/local/bin/yalla-worker",
		"/etc/yalla/control-plane.env",
		"/healthz",
		"/readyz",
		"structured JSON",
		"yalla.error.v1",
		"journalctl -u yalla-api -o json",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("deploy/systemd/README.md missing %q", want)
		}
	}
}

func TestSystemdArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestSystemdArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"systemd artifact static tests",
				"go test ./internal/release/... -run TestSystemdArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## systemd Operations Artifact",
				"deploy/systemd/yalla-api.service",
				"systemd-analyze verify",
				"go test ./internal/release/... -run TestSystemdArtifact",
			},
		},
	} {
		b, err := os.ReadFile(filepath.Join(root, tc.path))
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		body := string(b)
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q", tc.path, want)
			}
		}
	}
}

type systemdUnit struct {
	sections map[string]map[string]string
}

func parseSystemdUnit(t *testing.T, path string) systemdUnit {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	unit := systemdUnit{sections: map[string]map[string]string{}}
	section := ""
	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if unit.sections[section] == nil {
				unit.sections[section] = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s:%d invalid systemd assignment %q", path, i+1, line)
		}
		if section == "" {
			t.Fatalf("%s:%d assignment before section: %q", path, i+1, line)
		}
		unit.sections[section][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	for _, want := range []string{"Unit", "Service", "Install"} {
		if unit.sections[want] == nil {
			t.Fatalf("%s missing [%s] section", path, want)
		}
	}
	return unit
}

func assertSystemdServiceValue(t *testing.T, unit systemdUnit, key, want string) {
	t.Helper()
	assertSystemdSectionValue(t, unit, "Service", key, want)
}

func assertSystemdSectionValue(t *testing.T, unit systemdUnit, section, key, want string) {
	t.Helper()
	got, ok := unit.sections[section][key]
	if !ok {
		t.Fatalf("[%s].%s missing, want %q", section, key, want)
	}
	if got != want {
		t.Fatalf("[%s].%s = %q, want %q", section, key, got, want)
	}
}

func looksLikeRenderedSecret(value string) bool {
	trimmed := strings.Trim(value, `"'`)
	if trimmed == "" || strings.HasPrefix(trimmed, "<redacted:") {
		return false
	}
	lower := strings.ToLower(trimmed)
	return strings.Contains(lower, "postgres://") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "token=") ||
		strings.Contains(lower, "api_key=")
}
