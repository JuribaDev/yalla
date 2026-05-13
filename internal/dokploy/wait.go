package dokploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// WaitResult describes the final observed state of a wait primitive.
type WaitResult struct {
	Kind     string          `json:"kind"`
	Target   string          `json:"target"`
	Observed json.RawMessage `json:"observed,omitempty"`
	Status   string          `json:"status,omitempty"`
	Count    *int            `json:"count,omitempty"`
	Attempts int             `json:"attempts"`
	TimedOut bool            `json:"timed_out,omitempty"`
}

// WaitCompose polls compose-one until the desired or terminal status appears.
func WaitCompose(ctx context.Context, runner Runner, id, want string, interval time.Duration) (*WaitResult, error) {
	if interval <= 0 {
		interval = time.Second
	}
	for attempts := 1; ; attempts++ {
		res, err := runner.Call(ctx, "compose-one", Input{Query: map[string][]string{"composeId": {id}}})
		if err != nil {
			return nil, err
		}
		status := firstStringField(res.Body, "status", "deploymentStatus", "composeStatus", "state")
		if status == want || terminalStatus(status) {
			return &WaitResult{Kind: "compose", Target: id, Observed: res.Body, Status: status, Attempts: attempts}, nil
		}
		if err := sleepOrTimeout(ctx, interval); err != nil {
			return &WaitResult{Kind: "compose", Target: id, Observed: res.Body, Status: status, Attempts: attempts, TimedOut: true}, err
		}
	}
}

// WaitURL polls a URL until its HTTP status matches class.
func WaitURL(ctx context.Context, rawURL, class string, interval time.Duration) (*WaitResult, error) {
	if interval <= 0 {
		interval = time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for attempts := 1; ; attempts++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		resp, err := client.Do(req)
		status := 0
		if resp != nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
		if err == nil && statusMatchesClass(status, class) {
			return &WaitResult{Kind: "url", Target: rawURL, Status: strconv.Itoa(status), Attempts: attempts}, nil
		}
		if serr := sleepOrTimeout(ctx, interval); serr != nil {
			return &WaitResult{Kind: "url", Target: rawURL, Status: strconv.Itoa(status), Attempts: attempts, TimedOut: true}, serr
		}
	}
}

// WaitOrphans polls Docker containers by appName until count matches want.
func WaitOrphans(ctx context.Context, runner Runner, appName string, want int, interval time.Duration) (*WaitResult, error) {
	if interval <= 0 {
		interval = time.Second
	}
	for attempts := 1; ; attempts++ {
		res, err := runner.Call(ctx, "docker-getContainersByAppNameMatch", Input{Query: map[string][]string{"appName": {appName}}})
		if err != nil {
			return nil, err
		}
		count := countRecords(res.Body)
		if count == want {
			return &WaitResult{Kind: "orphans", Target: appName, Observed: res.Body, Count: &count, Attempts: attempts}, nil
		}
		if err := sleepOrTimeout(ctx, interval); err != nil {
			return &WaitResult{Kind: "orphans", Target: appName, Observed: res.Body, Count: &count, Attempts: attempts, TimedOut: true}, err
		}
	}
}

func sleepOrTimeout(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return yerr.New(yerr.CodeTimeout, "wait timed out").Wrap(ctx.Err())
	case <-t.C:
		return nil
	}
}

func terminalStatus(s string) bool {
	switch strings.ToLower(s) {
	case "idle", "done", "error":
		return true
	default:
		return false
	}
}

func statusMatchesClass(status int, class string) bool {
	switch strings.ToLower(class) {
	case "2xx":
		return status >= 200 && status < 300
	case "3xx":
		return status >= 300 && status < 400
	case "4xx":
		return status >= 400 && status < 500
	case "5xx":
		return status >= 500 && status < 600
	default:
		return strconv.Itoa(status) == class
	}
}

func firstStringField(raw json.RawMessage, fields ...string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	for _, f := range fields {
		if s := stringField(obj[f]); s != "" {
			return s
		}
	}
	return ""
}

func stringField(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func countRecords(raw json.RawMessage) int {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return len(arr)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, k := range []string{"data", "items", "containers", "results"} {
			if err := json.Unmarshal(obj[k], &arr); err == nil {
				return len(arr)
			}
		}
		if len(obj) == 0 {
			return 0
		}
	}
	return 0
}

// TimeoutError converts a last observed wait result into E_TIMEOUT.
func TimeoutError(last *WaitResult) error {
	count := 0
	if last.Count != nil {
		count = *last.Count
	}
	return yerr.Newf(yerr.CodeTimeout, "timed out waiting for %s %s", last.Kind, last.Target).
		WithHint(fmt.Sprintf("last observed status=%q count=%d", last.Status, count))
}
