package release_test

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const kubernetesManifestPath = "deploy/kubernetes/yalla-control-plane.yaml"

type kubernetesObject struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   kubeMetadata   `yaml:"metadata"`
	Spec       map[string]any `yaml:"spec"`
}

type kubeMetadata struct {
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels"`
}

func TestKubernetesArtifactDefinesAPIAndWorkerWorkloads(t *testing.T) {
	objects := readKubernetesObjects(t, filepath.Join(projectRoot(t), kubernetesManifestPath))

	api := requireKubernetesObject(t, objects, "Deployment", "yalla-api")
	worker := requireKubernetesObject(t, objects, "Deployment", "yalla-worker")
	requireKubernetesObject(t, objects, "Service", "yalla-api")

	assertDeploymentContainer(t, api, "yalla-api", "ghcr.io/juribadev/yalla-api:", "/usr/local/bin/yalla-api")
	assertDeploymentContainer(t, worker, "yalla-worker", "ghcr.io/juribadev/yalla-worker:", "/usr/local/bin/yalla-worker")
}

func TestKubernetesArtifactKeepsSecretsRuntimeOnly(t *testing.T) {
	objects := readKubernetesObjects(t, filepath.Join(projectRoot(t), kubernetesManifestPath))
	secretNames := map[string]bool{}
	for _, obj := range objects {
		if obj.Kind == "Secret" {
			t.Fatalf("%s must not check in Secret objects; bind an operator-created secret by name instead", kubernetesManifestPath)
		}
		if obj.Kind != "Deployment" {
			continue
		}
		podSpec := deploymentPodSpec(t, obj)
		for _, c := range kubeList(t, podSpec["containers"]) {
			for _, env := range kubeList(t, c["env"]) {
				name := kubeString(t, env["name"], "env.name")
				if isSecretShapedEnvName(name) {
					if _, ok := env["value"]; ok {
						t.Fatalf("%s deployment %s env %s uses literal value; use secretKeyRef", kubernetesManifestPath, obj.Metadata.Name, name)
					}
					ref := kubeMap(t, env["valueFrom"], "env.valueFrom")
					secretRef := kubeMap(t, ref["secretKeyRef"], "env.valueFrom.secretKeyRef")
					secretName := kubeString(t, secretRef["name"], "secretKeyRef.name")
					if secretName == "" {
						t.Fatalf("%s deployment %s env %s has empty secretKeyRef.name", kubernetesManifestPath, obj.Metadata.Name, name)
					}
					secretNames[secretName] = true
				}
			}
		}
	}
	if !secretNames["yalla-control-plane-secrets"] {
		t.Fatalf("%s must bind secret-shaped config from yalla-control-plane-secrets, got %v", kubernetesManifestPath, keysOf(secretNames))
	}
}

func TestKubernetesArtifactPinsLeastPrivilegePodSecurity(t *testing.T) {
	objects := readKubernetesObjects(t, filepath.Join(projectRoot(t), kubernetesManifestPath))
	for _, name := range []string{"yalla-api", "yalla-worker"} {
		obj := requireKubernetesObject(t, objects, "Deployment", name)
		podSpec := deploymentPodSpec(t, obj)
		if got := kubeBool(t, podSpec["automountServiceAccountToken"], "automountServiceAccountToken"); got {
			t.Fatalf("%s deployment %s must disable service-account token mounting", kubernetesManifestPath, name)
		}
		podSC := kubeMap(t, podSpec["securityContext"], "pod.securityContext")
		if !kubeBool(t, podSC["runAsNonRoot"], "pod.securityContext.runAsNonRoot") {
			t.Fatalf("%s deployment %s must set pod securityContext.runAsNonRoot=true", kubernetesManifestPath, name)
		}
		seccomp := kubeMap(t, podSC["seccompProfile"], "pod.securityContext.seccompProfile")
		if got := kubeString(t, seccomp["type"], "seccompProfile.type"); got != "RuntimeDefault" {
			t.Fatalf("%s deployment %s seccompProfile.type = %q, want RuntimeDefault", kubernetesManifestPath, name, got)
		}
		for _, c := range kubeList(t, podSpec["containers"]) {
			sc := kubeMap(t, c["securityContext"], "container.securityContext")
			if !kubeBool(t, sc["readOnlyRootFilesystem"], "container.securityContext.readOnlyRootFilesystem") {
				t.Fatalf("%s deployment %s must set readOnlyRootFilesystem=true", kubernetesManifestPath, name)
			}
			if kubeBool(t, sc["allowPrivilegeEscalation"], "container.securityContext.allowPrivilegeEscalation") {
				t.Fatalf("%s deployment %s must set allowPrivilegeEscalation=false", kubernetesManifestPath, name)
			}
			caps := kubeMap(t, sc["capabilities"], "container.securityContext.capabilities")
			if !contains(kubeStringList(t, caps["drop"], "capabilities.drop"), "ALL") {
				t.Fatalf("%s deployment %s must drop ALL capabilities", kubernetesManifestPath, name)
			}
		}
	}
}

func TestKubernetesArtifactDocumentsDryRunAndHealth(t *testing.T) {
	root := projectRoot(t)
	readmePath := filepath.Join(root, "deploy/kubernetes/README.md")
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read deploy/kubernetes/README.md: %v", err)
	}
	readme := string(b)
	for _, want := range []string{
		"kubectl apply --dry-run=server",
		"kubectl kustomize deploy/kubernetes",
		"/healthz",
		"/readyz",
		"structured JSON",
		"yalla-control-plane-secrets",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("deploy/kubernetes/README.md missing %q", want)
		}
	}

	objects := readKubernetesObjects(t, filepath.Join(root, kubernetesManifestPath))
	api := requireKubernetesObject(t, objects, "Deployment", "yalla-api")
	container := firstDeploymentContainer(t, api)
	for _, probeName := range []string{"livenessProbe", "readinessProbe"} {
		probe := kubeMap(t, container[probeName], probeName)
		httpGet := kubeMap(t, probe["httpGet"], probeName+".httpGet")
		path := kubeString(t, httpGet["path"], probeName+".httpGet.path")
		if probeName == "livenessProbe" && path != "/healthz" {
			t.Fatalf("livenessProbe path = %q, want /healthz", path)
		}
		if probeName == "readinessProbe" && path != "/readyz" {
			t.Fatalf("readinessProbe path = %q, want /readyz", path)
		}
	}
}

func TestKubernetesArtifactVerificationIsWiredIntoReleaseGates(t *testing.T) {
	root := projectRoot(t)
	for _, tc := range []struct {
		path string
		want []string
	}{
		{
			path: "scripts/verify.sh",
			want: []string{
				"go test ./internal/release/... -run TestKubernetesArtifact",
			},
		},
		{
			path: ".github/workflows/ci.yml",
			want: []string{
				"Kubernetes artifact static tests",
				"go test ./internal/release/... -run TestKubernetesArtifact",
			},
		},
		{
			path: "SECURITY.md",
			want: []string{
				"## Kubernetes Operations Artifact",
				"deploy/kubernetes/yalla-control-plane.yaml",
				"kubectl kustomize deploy/kubernetes",
				"go test ./internal/release/... -run TestKubernetesArtifact",
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

func readKubernetesObjects(t *testing.T, path string) []kubernetesObject {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	var objects []kubernetesObject
	for {
		var obj kubernetesObject
		err := dec.Decode(&obj)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode %s: %v", path, err)
		}
		if obj.Kind == "" {
			continue
		}
		objects = append(objects, obj)
	}
	if len(objects) == 0 {
		t.Fatalf("%s contained no Kubernetes objects", path)
	}
	return objects
}

func requireKubernetesObject(t *testing.T, objects []kubernetesObject, kind, name string) kubernetesObject {
	t.Helper()
	for _, obj := range objects {
		if obj.Kind == kind && obj.Metadata.Name == name {
			return obj
		}
	}
	t.Fatalf("missing Kubernetes %s/%s", kind, name)
	return kubernetesObject{}
}

func assertDeploymentContainer(t *testing.T, obj kubernetesObject, containerName, imagePrefix, command string) {
	t.Helper()
	container := firstDeploymentContainer(t, obj)
	if got := kubeString(t, container["name"], "container.name"); got != containerName {
		t.Fatalf("deployment %s container.name = %q, want %q", obj.Metadata.Name, got, containerName)
	}
	if got := kubeString(t, container["image"], "container.image"); !strings.HasPrefix(got, imagePrefix) {
		t.Fatalf("deployment %s image = %q, want prefix %q", obj.Metadata.Name, got, imagePrefix)
	}
	commandList := kubeStringList(t, container["command"], "container.command")
	if !contains(commandList, command) {
		t.Fatalf("deployment %s command = %v, want %s", obj.Metadata.Name, commandList, command)
	}
}

func deploymentPodSpec(t *testing.T, obj kubernetesObject) map[string]any {
	t.Helper()
	spec := kubeMap(t, obj.Spec, "deployment.spec")
	template := kubeMap(t, spec["template"], "deployment.spec.template")
	return kubeMap(t, template["spec"], "deployment.spec.template.spec")
}

func firstDeploymentContainer(t *testing.T, obj kubernetesObject) map[string]any {
	t.Helper()
	podSpec := deploymentPodSpec(t, obj)
	containers := kubeList(t, podSpec["containers"])
	if len(containers) != 1 {
		t.Fatalf("deployment %s containers len = %d, want 1", obj.Metadata.Name, len(containers))
	}
	return containers[0]
}

func kubeMap(t *testing.T, v any, field string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: got %T, want map", field, v)
	}
	return m
}

func kubeList(t *testing.T, v any) []map[string]any {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("got %T, want list", v)
	}
	out := make([]map[string]any, 0, len(raw))
	for i, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("list item %d: got %T, want map", i, item)
		}
		out = append(out, m)
	}
	return out
}

func kubeString(t *testing.T, v any, field string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s: got %T, want string", field, v)
	}
	return s
}

func kubeBool(t *testing.T, v any, field string) bool {
	t.Helper()
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("%s: got %T, want bool", field, v)
	}
	return b
}

func kubeStringList(t *testing.T, v any, field string) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: got %T, want list", field, v)
	}
	out := make([]string, 0, len(raw))
	for i, item := range raw {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s[%d]: got %T, want string", field, i, item)
		}
		out = append(out, s)
	}
	return out
}

func isSecretShapedEnvName(name string) bool {
	upper := strings.ToUpper(name)
	for _, frag := range forbiddenSecretEnvFragments {
		if strings.Contains(upper, frag) {
			return true
		}
	}
	return false
}

func keysOf(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
