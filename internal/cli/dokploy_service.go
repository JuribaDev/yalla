package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/dokploy"
)

func newDokployRunner(cfg *config.Config, build BuildInfo, timeout time.Duration) (*dokploy.HTTPRunner, error) {
	scheme, headerName, basePath := resolveAPIClientDefaults(api.Default())
	cli, err := api.NewClient(api.ClientConfig{
		BaseURL:        cfg.BaseURL,
		Token:          cfg.Token,
		AuthScheme:     scheme,
		AuthHeaderName: headerName,
		BasePathPrefix: basePath,
		UserAgent:      "yalla/" + build.Version,
		Timeout:        timeout,
		MaxRetries:     0,
	})
	if err != nil {
		return nil, err
	}
	return dokploy.NewHTTPRunner(api.Default(), cli), nil
}

func configFromCommand(cmd *cobra.Command) *config.Config {
	return config.FromContext(cmd.Context())
}
