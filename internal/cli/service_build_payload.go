package cli

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"gopkg.in/yaml.v3"
)

type serviceBuildFlags struct {
	BuildType         string
	Repo              string
	Branch            string
	RootDir           string
	BuildCommand      string
	OutputDir         string
	InstallCommand    string
	SPAFallback       bool
	Port              int
	Context           string
	Dockerfile        string
	Target            string
	BuildArgs         []string
	ComposeFile       string
	EnvFile           string
	ProjectName       string
	ComposeService    string
	Image             string
	RegistrySecretRef string
	Command           string
	Args              []string
	FromFile          string
}

type serviceSpecFile struct {
	ServiceID     string         `json:"service_id" yaml:"service_id"`
	EnvironmentID string         `json:"environment_id" yaml:"environment_id"`
	Name          string         `json:"name" yaml:"name"`
	DisplayName   string         `json:"display_name" yaml:"display_name"`
	Kind          string         `json:"kind" yaml:"kind"`
	BuildConfig   map[string]any `json:"build_config" yaml:"build_config"`
}

func serviceCreateBodyFromFlags(serviceID, environmentID, name, displayName, kind string, flags serviceBuildFlags) (map[string]any, string, string, error) {
	fileSpec, err := loadServiceSpecFile(flags.FromFile)
	if err != nil {
		return nil, "", "", err
	}
	if fileSpec != nil {
		if strings.TrimSpace(serviceID) == "" {
			serviceID = fileSpec.ServiceID
		}
		if strings.TrimSpace(environmentID) == "" {
			environmentID = fileSpec.EnvironmentID
		}
		if strings.TrimSpace(name) == "" {
			name = fileSpec.Name
		}
		if strings.TrimSpace(displayName) == "" {
			displayName = fileSpec.DisplayName
		}
		if strings.TrimSpace(kind) == "" {
			kind = fileSpec.Kind
		}
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = name
	}
	if strings.TrimSpace(kind) == "" {
		kind = "application"
	}
	if strings.TrimSpace(serviceID) == "" {
		serviceID = domain.MustNewID(domain.KindService).String()
	}
	body := map[string]any{
		"service_id":   strings.TrimSpace(serviceID),
		"slug":         strings.TrimSpace(name),
		"display_name": strings.TrimSpace(displayName),
		"kind":         strings.TrimSpace(kind),
	}
	if fileSpec != nil && len(fileSpec.BuildConfig) > 0 {
		body["build_config"] = fileSpec.BuildConfig
		return body, environmentID, name, nil
	}
	build, err := buildConfigPayload(flags)
	if err != nil {
		return nil, "", "", err
	}
	if build != nil {
		body["build_config"] = build
	}
	return body, environmentID, name, nil
}

func buildConfigPayload(flags serviceBuildFlags) (map[string]any, error) {
	if strings.TrimSpace(flags.FromFile) != "" {
		spec, err := loadServiceSpecFile(flags.FromFile)
		if err != nil {
			return nil, err
		}
		if spec == nil || len(spec.BuildConfig) == 0 {
			return nil, yerr.New(yerr.CodeInvalidInput, "service spec file does not contain build_config").WithHint("include a build_config object or pass --build-type")
		}
		return spec.BuildConfig, nil
	}

	buildType := strings.TrimSpace(flags.BuildType)
	if buildType == "" {
		return nil, nil
	}
	source := map[string]any{}
	config := map[string]any{}
	sourceType := "manual"
	if strings.TrimSpace(flags.Repo) != "" {
		sourceType = "git"
		source["repo"] = strings.TrimSpace(flags.Repo)
	}
	if strings.TrimSpace(flags.Branch) != "" {
		source["branch"] = strings.TrimSpace(flags.Branch)
	}
	if flags.Port > 0 {
		config["port"] = flags.Port
	}
	switch buildType {
	case "static":
		if sourceType != "git" {
			return nil, yerr.New(yerr.CodeInvalidInput, "static build requires a repository").WithHint("pass --repo")
		}
		if strings.TrimSpace(flags.OutputDir) == "" {
			return nil, yerr.New(yerr.CodeInvalidInput, "static build requires an output directory").WithHint("pass --output-dir")
		}
		setString(config, "root_dir", flags.RootDir)
		setString(config, "build_command", flags.BuildCommand)
		setString(config, "output_dir", flags.OutputDir)
		setString(config, "install_command", flags.InstallCommand)
		config["spa_fallback"] = flags.SPAFallback
	case "dockerfile":
		if sourceType != "git" {
			return nil, yerr.New(yerr.CodeInvalidInput, "dockerfile build requires a repository").WithHint("pass --repo")
		}
		if strings.TrimSpace(flags.Context) == "" {
			return nil, yerr.New(yerr.CodeInvalidInput, "dockerfile build requires a context").WithHint("pass --context")
		}
		if strings.TrimSpace(flags.Dockerfile) == "" {
			return nil, yerr.New(yerr.CodeInvalidInput, "dockerfile build requires a Dockerfile path").WithHint("pass --dockerfile")
		}
		setString(config, "context", flags.Context)
		setString(config, "dockerfile", flags.Dockerfile)
		setString(config, "target", flags.Target)
		if len(flags.BuildArgs) > 0 {
			config["build_args"] = keyValueList(flags.BuildArgs)
		}
	case "compose":
		if strings.TrimSpace(flags.ComposeFile) == "" {
			return nil, yerr.New(yerr.CodeInvalidInput, "compose build requires a compose file").WithHint("pass --compose-file")
		}
		setString(source, "compose_file", flags.ComposeFile)
		setString(config, "env_file", flags.EnvFile)
		setString(config, "project_name", flags.ProjectName)
		setString(config, "compose_service", flags.ComposeService)
	case "image":
		if strings.TrimSpace(flags.Image) == "" {
			return nil, yerr.New(yerr.CodeInvalidInput, "image build requires an image").WithHint("pass --image")
		}
		sourceType = "image"
		setString(source, "image", flags.Image)
		setString(config, "registry_secret_ref", flags.RegistrySecretRef)
		setString(config, "command", flags.Command)
		if len(flags.Args) > 0 {
			config["args"] = flags.Args
		}
	default:
		return nil, yerr.Newf(yerr.CodeInvalidInput, "unsupported build type %q", buildType).WithHint("use static, dockerfile, compose, or image")
	}
	return map[string]any{
		"build_type":  buildType,
		"source_type": sourceType,
		"source":      source,
		"config":      config,
	}, nil
}

func loadServiceSpecFile(path string) (*serviceSpecFile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, yerr.Newf(yerr.CodeConfig, "read service spec: %v", err)
	}
	var spec serviceSpecFile
	if json.Unmarshal(raw, &spec) == nil && (spec.ServiceID != "" || len(spec.BuildConfig) > 0) {
		return &spec, nil
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "parse service spec: %v", err)
	}
	return &spec, nil
}

func setString(m map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		m[key] = strings.TrimSpace(value)
	}
}

func keyValueList(items []string) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			out[strings.TrimSpace(item)] = ""
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func addServiceBuildFlags(cmd *cobra.Command, opts *serviceBuildFlags) {
	f := cmd.Flags()
	f.StringVar(&opts.BuildType, "build-type", "", "build type: static, dockerfile, compose, or image")
	f.StringVar(&opts.Repo, "repo", "", "source Git repository")
	f.StringVar(&opts.Branch, "branch", "", "source Git branch")
	f.StringVar(&opts.RootDir, "root-dir", "", "static source root directory")
	f.StringVar(&opts.BuildCommand, "build-command", "", "static build command")
	f.StringVar(&opts.OutputDir, "output-dir", "", "static output directory")
	f.StringVar(&opts.InstallCommand, "install-command", "", "static install command")
	f.BoolVar(&opts.SPAFallback, "spa-fallback", false, "enable static SPA fallback")
	f.IntVar(&opts.Port, "port", 0, "runtime port")
	f.StringVar(&opts.Context, "context", "", "Docker build context")
	f.StringVar(&opts.Dockerfile, "dockerfile", "", "Dockerfile path")
	f.StringVar(&opts.Target, "target", "", "Docker build target")
	f.StringArrayVar(&opts.BuildArgs, "build-arg", nil, "Docker build arg KEY=VALUE")
	f.StringVar(&opts.ComposeFile, "compose-file", "", "Docker Compose file path")
	f.StringVar(&opts.EnvFile, "env-file", "", "compose env file path")
	f.StringVar(&opts.ProjectName, "project-name", "", "compose project name")
	f.StringVar(&opts.ComposeService, "compose-service", "", "compose service to deploy")
	f.StringVar(&opts.Image, "image", "", "prebuilt image reference")
	f.StringVar(&opts.RegistrySecretRef, "registry-secret-ref", "", "registry credential secret reference")
	f.StringVar(&opts.Command, "command", "", "runtime command")
	f.StringArrayVar(&opts.Args, "args", nil, "runtime args")
	f.StringVar(&opts.FromFile, "from-file", "", "YAML or JSON service spec file")
}

func sourceForBuildType(buildType string) string {
	switch buildType {
	case "image":
		return "image"
	case "static", "dockerfile", "compose":
		return "git"
	default:
		return "manual"
	}
}

func sourceRefFromBuildFlags(flags serviceBuildFlags) string {
	if strings.TrimSpace(flags.Branch) != "" {
		return strings.TrimSpace(flags.Branch)
	}
	if strings.TrimSpace(flags.Image) != "" {
		return strings.TrimSpace(flags.Image)
	}
	if flags.Port > 0 {
		return strconv.Itoa(flags.Port)
	}
	return ""
}
