package dokploy

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// ReadAppMonitoring reads Dokploy's application.readAppMonitoring endpoint.
func (c *Client) ReadAppMonitoring(ctx context.Context, in ReadAppMonitoringInput) (MonitoringPayload, error) {
	appName := strings.TrimSpace(in.AppName)
	if appName == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "app_name", Reason: "is required"})
	}
	path := "/application.readAppMonitoring?" + url.Values{"appName": {appName}}.Encode()
	var out MonitoringPayload
	if err := c.do(ctx, http.MethodGet, path, "/application.readAppMonitoring", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetContainerMetrics reads Dokploy's user.getContainerMetrics endpoint.
func (c *Client) GetContainerMetrics(ctx context.Context, in GetContainerMetricsInput) (MonitoringPayload, error) {
	values, err := monitoringNodeQuery(in.URL, in.Token, in.DataPoints)
	if err != nil {
		return nil, err
	}
	appName := strings.TrimSpace(in.AppName)
	if appName == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "app_name", Reason: "is required"})
	}
	values.Set("appName", appName)
	path := "/user.getContainerMetrics?" + values.Encode()
	var out MonitoringPayload
	if err := c.do(ctx, http.MethodGet, path, "/user.getContainerMetrics", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetServerMetrics reads Dokploy's server.getServerMetrics endpoint.
func (c *Client) GetServerMetrics(ctx context.Context, in GetServerMetricsInput) (MonitoringPayload, error) {
	values, err := monitoringNodeQuery(in.URL, in.Token, in.DataPoints)
	if err != nil {
		return nil, err
	}
	path := "/server.getServerMetrics?" + values.Encode()
	var out MonitoringPayload
	if err := c.do(ctx, http.MethodGet, path, "/server.getServerMetrics", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetUserServerMetrics reads Dokploy's user.getServerMetrics endpoint.
func (c *Client) GetUserServerMetrics(ctx context.Context) (MonitoringPayload, error) {
	var out MonitoringPayload
	if err := c.do(ctx, http.MethodGet, "/user.getServerMetrics", "/user.getServerMetrics", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func monitoringNodeQuery(rawURL, token string, dataPoints int) (url.Values, error) {
	rawURL = strings.TrimSpace(rawURL)
	token = strings.TrimSpace(token)
	var violations []apierr.FieldViolation
	if rawURL == "" {
		violations = append(violations, apierr.FieldViolation{Field: "url", Reason: "is required"})
	}
	if token == "" {
		violations = append(violations, apierr.FieldViolation{Field: "token", Reason: "is required"})
	}
	if dataPoints < 1 {
		violations = append(violations, apierr.FieldViolation{Field: "data_points", Reason: "must be positive"})
	}
	if len(violations) > 0 {
		return nil, apierr.InvalidInput(violations...)
	}
	return url.Values{
		"url":        {rawURL},
		"token":      {token},
		"dataPoints": {strconv.Itoa(dataPoints)},
	}, nil
}
