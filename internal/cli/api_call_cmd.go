package cli

import (
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newAPICallCommand() *cobra.Command {
	var inputPath, data string
	var dryRun, strictAppName, getOrCreate bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "call <operationId>",
		Short: "Unsupported raw operation executor",
		Long: `Raw operation execution is not available in backend-only CLI mode.

Use product commands that call the Yalla Control Plane API, or inspect the
backend contract with ` + "`yalla api operations`" + ` and ` + "`yalla schema`" + `.
Any future diagnostic escape hatch must be backend-mediated, policy-checked,
audited, and explicitly admin-only.`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			return yerr.New(yerr.CodeUnsupported, "raw operation execution is not available in backend-only CLI mode").
				WithHint("use a Yalla backend product command or an audited backend admin diagnostic route")
		},
	}
	cmd.Flags().StringVar(&inputPath, "input", "", "ignored compatibility flag")
	cmd.Flags().StringVar(&data, "data", "", "ignored compatibility flag")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "ignored compatibility flag")
	cmd.Flags().BoolVar(&strictAppName, "strict-appname", false, "ignored compatibility flag")
	cmd.Flags().BoolVar(&getOrCreate, "get-or-create", false, "ignored compatibility flag")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "ignored compatibility flag")
	return cmd
}
