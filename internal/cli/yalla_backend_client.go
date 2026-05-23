package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type yallaEnvelope struct {
	Data json.RawMessage `json:"data"`
}

func newYallaAPIClient(cfg *config.Config, build BuildInfo, timeout time.Duration) (*api.Client, error) {
	if cfg == nil {
		return nil, yerr.New(yerr.CodeConfig, "yalla config is not initialised")
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, yerr.New(yerr.CodeConfig, "no Yalla API URL configured").
			WithHint("run `yalla auth login`, set YALLA_BASE_URL, or pass --base-url")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, yerr.New(yerr.CodeAuth, "no Yalla API token configured").
			WithHint("run `yalla auth login`, set YALLA_TOKEN, or pass --token")
	}
	return api.NewClient(api.ClientConfig{
		BaseURL:    cfg.BaseURL,
		Token:      cfg.Token,
		AuthScheme: api.AuthSchemeBearer,
		UserAgent:  "yalla/" + build.Version,
		Timeout:    timeout,
		MaxRetries: 2,
	})
}

func configFromCommand(cmd interface{ Context() context.Context }) *config.Config {
	return config.FromContext(cmd.Context())
}

func yallaJSONRequest(ctx context.Context, cli *api.Client, method, path string, body any, idempotent bool) (json.RawMessage, *api.Result, error) {
	return yallaJSONRequestWithHeaders(ctx, cli, method, path, body, nil, idempotent)
}

func yallaJSONRequestWithHeaders(ctx context.Context, cli *api.Client, method, path string, body any, headers http.Header, idempotent bool) (json.RawMessage, *api.Result, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, nil, yerr.Newf(yerr.CodeInvalidInput, "encode request body: %v", err)
		}
	}
	res, err := cli.Do(ctx, &api.Request{
		Method:      method,
		Path:        path,
		Headers:     headers,
		Body:        payload,
		ContentType: api.ContentTypeJSON,
		Idempotent:  idempotent,
	})
	if err != nil {
		return nil, nil, errAsTyped(err, yerr.CodeNetwork)
	}
	if !res.Success() {
		return nil, res, yallaResultError(res)
	}
	return unwrapYallaData(res.Body), res, nil
}

func yallaBackendRegistry(ctx context.Context, cfg *config.Config, build BuildInfo) (*api.Registry, error) {
	if cfg == nil || strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, yerr.New(yerr.CodeConfig, "no Yalla API URL configured").
			WithHint("run `yalla auth login`, set YALLA_BASE_URL, or pass --base-url")
	}
	cli, err := api.NewClient(api.ClientConfig{
		BaseURL:    cfg.BaseURL,
		Token:      cfg.Token,
		AuthScheme: api.AuthSchemeBearer,
		UserAgent:  "yalla/" + build.Version,
		MaxRetries: 2,
	})
	if err != nil {
		return nil, err
	}
	res, err := cli.Do(ctx, &api.Request{
		Method:     http.MethodGet,
		Path:       "/openapi.json",
		Idempotent: true,
	})
	if err != nil {
		return nil, errAsTyped(err, yerr.CodeNetwork)
	}
	if !res.Success() {
		return nil, yallaResultError(res)
	}
	reg, err := api.Load(res.Body)
	if err != nil {
		return nil, yerr.Newf(yerr.CodeServer, "Yalla API returned an invalid OpenAPI document: %v", err)
	}
	return reg, nil
}

func yallaResultError(res *api.Result) error {
	if res == nil {
		return yerr.New(yerr.CodeInternal, "nil Yalla API result")
	}
	code := res.AsError().Code
	msg := "Yalla API responded with HTTP " + http.StatusText(res.Status)
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &env); err == nil {
		if env.Error.Message != "" {
			msg = env.Error.Message
		}
		if mapped := yerr.Code(env.Error.Code); mapped != "" {
			code = mapped
		}
		e := yerr.New(code, msg)
		if env.Error.Hint != "" {
			e = e.WithHint(env.Error.Hint)
		}
		return e
	}
	return res.AsError()
}

func unwrapYallaData(body []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return json.RawMessage(`{}`)
	}
	var env yallaEnvelope
	if err := json.Unmarshal(trimmed, &env); err == nil && len(env.Data) > 0 {
		return env.Data
	}
	return json.RawMessage(trimmed)
}

func yallaPath(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			b.WriteByte('/')
		}
		b.WriteString(strings.Trim(p, "/"))
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

func pathID(id string) string {
	return url.PathEscape(strings.TrimSpace(id))
}

func errAsTyped(err error, fallback yerr.Code) error {
	if err == nil {
		return nil
	}
	typed := yerr.From(err)
	if typed.Code != yerr.CodeInternal {
		return typed
	}
	return yerr.New(fallback, typed.Message).Wrap(err)
}
