package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newWaitCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "wait", Short: "Wait for Yalla backend jobs or deployments", SilenceErrors: true, SilenceUsage: true}
	cmd.AddCommand(newWaitJobCommand(), newWaitDeploymentCommand(), newWaitURLCommand())
	return cmd
}

func newWaitJobCommand() *cobra.Command {
	var id, status string
	var timeout, interval time.Duration
	cmd := &cobra.Command{Use: "job", Short: "Wait for a backend job status", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if strings.TrimSpace(id) == "" {
			return yerr.New(yerr.CodeInvalidInput, "job ID is required").WithHint("pass --job-id")
		}
		return waitBackendResource(c, yallaPath("v1/jobs", pathID(id)), "job", status, timeout, interval)
	}}
	cmd.Flags().StringVar(&id, "job-id", "", "Yalla job ID")
	cmd.Flags().StringVar(&status, "status", "succeeded", "desired terminal status")
	cmd.Flags().DurationVar(&timeout, "timeout", 300*time.Second, "maximum wait")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "poll interval")
	return cmd
}

func newWaitDeploymentCommand() *cobra.Command {
	var id, status string
	var timeout, interval time.Duration
	cmd := &cobra.Command{Use: "deployment", Short: "Wait for a deployment status", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if strings.TrimSpace(id) == "" {
			return yerr.New(yerr.CodeInvalidInput, "deployment ID is required").WithHint("pass --deployment-id")
		}
		return waitBackendResource(c, yallaPath("v1/deployments", pathID(id)), "deployment", status, timeout, interval)
	}}
	cmd.Flags().StringVar(&id, "deployment-id", "", "Yalla deployment ID")
	cmd.Flags().StringVar(&status, "status", "succeeded", "desired terminal status")
	cmd.Flags().DurationVar(&timeout, "timeout", 300*time.Second, "maximum wait")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "poll interval")
	return cmd
}

func waitBackendResource(c *cobra.Command, path, resourceKey, want string, timeout, interval time.Duration) error {
	r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
	cli, err := newYallaAPIClient(configFromCommand(c), BuildInfoFromContext(c.Context()), 0)
	if err != nil {
		return err
	}
	ctx := c.Context()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if interval <= 0 {
		interval = time.Second
	}
	var last json.RawMessage
	for {
		data, _, err := yallaJSONRequest(ctx, cli, http.MethodGet, path, nil, true)
		if err != nil {
			return err
		}
		last = data
		if resourceStatus(data, resourceKey) == want {
			if r.JSON() {
				return r.Data(data)
			}
			r.Human(want)
			return nil
		}
		select {
		case <-ctx.Done():
			return yerr.Newf(yerr.CodeTimeout, "timed out waiting for %s status %q", resourceKey, want).
				WithHint(string(last))
		case <-time.After(interval):
		}
	}
}

func resourceStatus(data json.RawMessage, resourceKey string) string {
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		return ""
	}
	raw := outer[resourceKey]
	if len(raw) == 0 {
		raw = data
	}
	var obj struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.Status
}

func newWaitURLCommand() *cobra.Command {
	var rawURL, class string
	var timeout, interval time.Duration
	cmd := &cobra.Command{Use: "url", Short: "Wait for an HTTP status class", Args: cobra.NoArgs, SilenceErrors: true, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		if strings.TrimSpace(rawURL) == "" {
			return yerr.New(yerr.CodeInvalidInput, "URL is required").WithHint("pass --url")
		}
		return waitURL(c, rawURL, class, timeout, interval)
	}}
	cmd.Flags().StringVar(&rawURL, "url", "", "URL to probe")
	cmd.Flags().StringVar(&class, "status-class", "2xx", "desired status class")
	cmd.Flags().DurationVar(&timeout, "timeout", 120*time.Second, "maximum wait")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "poll interval")
	return cmd
}

func waitURL(c *cobra.Command, rawURL, class string, timeout, interval time.Duration) error {
	r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
	ctx := c.Context()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if interval <= 0 {
		interval = time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return yerr.Newf(yerr.CodeInvalidInput, "invalid URL %q: %v", rawURL, err)
		}
		res, err := client.Do(req)
		if err == nil {
			_ = res.Body.Close()
			if statusMatchesClass(res.StatusCode, class) {
				doc := map[string]any{"url": rawURL, "status": http.StatusText(res.StatusCode), "status_code": res.StatusCode}
				if r.JSON() {
					return r.Data(doc)
				}
				r.Human(http.StatusText(res.StatusCode))
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return yerr.Newf(yerr.CodeTimeout, "timed out waiting for %s to return %s", rawURL, class)
		case <-time.After(interval):
		}
	}
}

func statusMatchesClass(status int, class string) bool {
	if len(class) != 3 || class[1:] != "xx" {
		return false
	}
	if status < 100 || status > 599 {
		return false
	}
	return strconv.Itoa(status/100)+"xx" == class
}
