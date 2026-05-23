package cli

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/spf13/cobra"
)

func newDeployCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "deploy", Short: "Deploy services through the Yalla backend", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newDeployComposeCommand())
	return cmd
}

type deployComposeOptions struct {
	ServiceID      string
	Source         string
	SourceRef      string
	IdempotencyKey string
	Wait           bool
	PollInterval   time.Duration
	Timeout        time.Duration
}

func newDeployComposeCommand() *cobra.Command {
	var opts deployComposeOptions
	cmd := &cobra.Command{Use: "compose", Short: "Deploy a Docker Compose stack", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
		if strings.TrimSpace(opts.ServiceID) == "" {
			return yerr.New(yerr.CodeInvalidInput, "service ID is required").WithHint("pass --service-id")
		}
		if strings.TrimSpace(opts.Source) == "" {
			opts.Source = "manual"
		}
		if strings.TrimSpace(opts.IdempotencyKey) == "" {
			opts.IdempotencyKey = generatedIdempotencyKey()
		}
		data, err := deployService(c, opts.ServiceID, opts.Source, opts.SourceRef, opts.IdempotencyKey, opts.Timeout)
		if err != nil {
			return err
		}
		if opts.Wait {
			if waited, waitErr := waitOnBackendJobFromData(c, data, opts.Timeout, opts.PollInterval); waitErr != nil {
				return waitErr
			} else if waited != nil {
				data = waited
			}
		}
		if r.JSON() {
			return r.Data(data)
		}
		r.Human("deployment accepted")
		return nil
	}}
	cmd.Flags().StringVar(&opts.ServiceID, "service-id", "", "Yalla service ID")
	cmd.Flags().StringVar(&opts.Source, "source", "manual", "deployment source: manual, git, or image")
	cmd.Flags().StringVar(&opts.SourceRef, "source-ref", "", "source ref, commit, image, or label")
	cmd.Flags().StringVar(&opts.IdempotencyKey, "idempotency-key", "", "idempotency key for safe retries")
	cmd.Flags().BoolVar(&opts.Wait, "wait", false, "wait for deployment job to complete")
	cmd.Flags().DurationVar(&opts.PollInterval, "poll-interval", time.Second, "wait polling interval")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "deployment timeout")
	return cmd
}

func generatedIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(b[:])
}
