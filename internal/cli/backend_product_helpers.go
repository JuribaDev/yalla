package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func yallaBackendRequest(c *cobra.Command, method, path string, body any, headers http.Header, timeout time.Duration) (json.RawMessage, error) {
	cli, err := newYallaAPIClient(configFromCommand(c), BuildInfoFromContext(c.Context()), timeout)
	if err != nil {
		return nil, err
	}
	data, _, err := yallaJSONRequestWithHeaders(c.Context(), cli, method, path, body, headers, method == http.MethodGet)
	return data, err
}

func renderBackendData(c *cobra.Command, data json.RawMessage, human string) error {
	r := rendererFromContext(c, IOStreamsFromContext(c.Context()))
	if r.JSON() {
		return r.Data(data)
	}
	r.Human(human)
	return nil
}

func requireFlag(value, label, flag string) error {
	if strings.TrimSpace(value) != "" {
		return nil
	}
	return yerr.New(yerr.CodeInvalidInput, label+" is required").WithHint("pass " + flag)
}

func addWaitFlags(cmd *cobra.Command, wait *bool, timeout *time.Duration, pollInterval *time.Duration) {
	cmd.Flags().BoolVar(wait, "wait", false, "wait for the returned job to complete")
	cmd.Flags().DurationVar(timeout, "timeout", 5*time.Minute, "request or wait timeout")
	cmd.Flags().DurationVar(pollInterval, "poll-interval", time.Second, "wait polling interval")
}

func waitOnBackendJobFromData(c *cobra.Command, data json.RawMessage, timeout, pollInterval time.Duration) (json.RawMessage, error) {
	jobID := extractStringFromRaw(data, "job_id")
	if jobID == "" {
		jobID = extractNestedStringFromRaw(data, "job", "id")
	}
	if jobID == "" {
		return nil, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		got, err := yallaBackendRequest(c, http.MethodGet, yallaPath("v1/jobs", pathID(jobID)), nil, nil, timeout)
		if err != nil {
			return nil, err
		}
		status := extractNestedStringFromRaw(got, "job", "status")
		if status == "succeeded" || status == "failed" || status == "cancelled" || status == "dead_letter" {
			return got, nil
		}
		if time.Now().After(deadline) {
			return nil, yerr.New(yerr.CodeTimeout, "timed out waiting for job").WithHint("increase --timeout")
		}
		time.Sleep(pollInterval)
	}
}

func extractStringFromRaw(data json.RawMessage, key string) string {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return ""
	}
	v, _ := obj[key].(string)
	return v
}

func extractNestedStringFromRaw(data json.RawMessage, parent, key string) string {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return ""
	}
	nested, _ := obj[parent].(map[string]any)
	v, _ := nested[key].(string)
	return v
}
