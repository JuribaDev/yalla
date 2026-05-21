package cli

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	"github.com/JuribaDev/yalla/internal/credentials"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

const (
	credentialService = "yalla"
	authStoreKeyring  = "keyring"
	authStoreConfig   = "config"
)

var credentialStoreFactory = func() credentials.Store {
	return credentials.KeyringStore{}
}

// newAuthCommand groups credential-introspection commands. Today it only
// hosts `auth status`; future stories may add `auth login`, `auth logout`,
// or `auth refresh` without changing the existing surface.
func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Inspect Yalla API credentials and connection settings",
		Long: `Inspect the authentication state yalla will use for Yalla API calls.

The command never echoes the token value; it only reports presence,
provenance, and whether the resolved configuration is sufficient to make a
live API call.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newAuthStatusCommand())
	cmd.AddCommand(newAuthLoginCommand())
	cmd.AddCommand(newAuthLogoutCommand())
	cmd.AddCommand(newAuthWhoamiCommand())
	return cmd
}

// authStatusDoc is the JSON shape returned by `yalla auth status`. The
// nested objects carry presence + source + (for non-secret fields) value
// so an agent can branch on Configured/Ready without parsing strings, while
// a human reader still gets the contextual information.
type authStatusDoc struct {
	BaseURL    fieldDoc `json:"base_url"`
	Token      fieldDoc `json:"token"`
	ConfigPath fieldDoc `json:"config_path"`
	NoInput    bool     `json:"no_input"`
	Output     string   `json:"output"`
	Ready      bool     `json:"ready"`
	Reason     string   `json:"reason,omitempty"`
}

// fieldDoc is the per-field shape used inside authStatusDoc. Value is
// omitted when the field is a secret so the JSON payload stays scrubbed
// without relying on the redactor.
type fieldDoc struct {
	Set    bool          `json:"set"`
	Source config.Source `json:"source"`
	Value  string        `json:"value,omitempty"`
}

type authTokenDoc struct {
	Set     bool   `json:"set"`
	Source  string `json:"source"`
	Account string `json:"account,omitempty"`
}

type authUserDoc struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

type authLoginDoc struct {
	URL                  string       `json:"url"`
	ConfigPath           string       `json:"config_path,omitempty"`
	Token                authTokenDoc `json:"token"`
	User                 authUserDoc  `json:"user,omitempty"`
	ActiveOrganizationID string       `json:"active_organization_id,omitempty"`
	Verified             bool         `json:"verified"`
}

type authLogoutDoc struct {
	URL     string       `json:"url"`
	Token   authTokenDoc `json:"token"`
	Removed bool         `json:"removed"`
}

func newAuthStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether yalla can authenticate against the Yalla API",
		Long: `Report the resolved authentication state without contacting the Yalla
API. The command always exits 0 when it can compute the status (so agents
can rely on a non-error envelope to detect partial configuration); the
` + "`ready`" + ` boolean inside the payload is the authoritative
"can yalla make an API call right now?" signal.`,
		Example: `  yalla auth status
  yalla --json auth status`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg := config.FromContext(c.Context())
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runAuthStatus(r, cfg)
		},
	}
	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	var (
		loginURL   string
		tokenStdin bool
		skipVerify bool
		store      string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store a URL and API token for yalla",
		Long: `Store the URL and API token yalla will use for API calls.

By default the URL is written to the yalla config file and the token is
stored in the host operating system credential store. Use --token-stdin for
automation so the token does not appear in shell history or process lists.`,
		Example: `  yalla auth login
  printf '%s' "$YALLA_TOKEN" | yalla auth login --url https://api.yalla.example --token-stdin --json`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			cfg := config.FromContext(ctx)
			streams := IOStreamsFromContext(ctx)
			r := rendererFromContext(c, streams)
			return runAuthLogin(ctx, r, streams, cfg, authLoginOptions{
				URL:        loginURL,
				TokenStdin: tokenStdin,
				SkipVerify: skipVerify,
				Store:      store,
				Build:      BuildInfoFromContext(ctx),
			})
		},
	}
	cmd.Flags().StringVar(&loginURL, "url", "", "Yalla API URL")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read the Yalla API token from stdin")
	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "store credentials without calling the API")
	cmd.Flags().StringVar(&store, "store", authStoreKeyring, "where to store the token: keyring or config")
	return cmd
}

func newAuthLogoutCommand() *cobra.Command {
	var logoutURL string
	cmd := &cobra.Command{
		Use:           "logout",
		Short:         "Remove the stored API token",
		Long:          `Remove the API token stored for the active URL from the host credential store.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg := config.FromContext(c.Context())
			streams := IOStreamsFromContext(c.Context())
			r := rendererFromContext(c, streams)
			return runAuthLogout(r, cfg, logoutURL)
		},
	}
	cmd.Flags().StringVar(&logoutURL, "url", "", "URL whose stored token should be removed")
	return cmd
}

func newAuthWhoamiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "whoami",
		Short:         "Show the authenticated yalla user",
		Long:          `Call the API and show the authenticated user and active organization.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			cfg := config.FromContext(ctx)
			streams := IOStreamsFromContext(ctx)
			r := rendererFromContext(c, streams)
			identity, err := verifyAuthIdentity(ctx, cfg.BaseURL, cfg.Token, BuildInfoFromContext(ctx))
			if err != nil {
				return err
			}
			doc := authLoginDoc{
				URL:                  cfg.BaseURL,
				Token:                authTokenDoc{Set: cfg.HasToken(), Source: string(cfg.TokenSource), Account: credentialAccountForURL(cfg.BaseURL)},
				User:                 identity.User,
				ActiveOrganizationID: identity.ActiveOrganizationID,
				Verified:             true,
			}
			if r.JSON() {
				return r.Data(doc)
			}
			renderWhoamiHuman(r, doc)
			return nil
		},
	}
	return cmd
}

type authLoginOptions struct {
	URL        string
	TokenStdin bool
	SkipVerify bool
	Store      string
	Build      BuildInfo
}

type authIdentity struct {
	User                 authUserDoc
	ActiveOrganizationID string
}

func runAuthLogin(ctx context.Context, r *output.Renderer, streams IOStreams, cfg *config.Config, opts authLoginOptions) error {
	storeMode := strings.TrimSpace(opts.Store)
	if storeMode == "" {
		storeMode = authStoreKeyring
	}
	if storeMode != authStoreKeyring && storeMode != authStoreConfig {
		return yerr.Newf(yerr.CodeInvalidInput, "unknown token store %q", opts.Store).
			WithHint("use --store keyring or --store config")
	}

	loginURL := strings.TrimSpace(opts.URL)
	if loginURL == "" {
		if cfg.NoInput {
			return yerr.New(yerr.CodeNoInput, "auth login requires a URL").
				WithHint("pass --url <url>")
		}
		var err error
		loginURL, err = promptLine(streams, "URL: ")
		if err != nil {
			return err
		}
	}
	loginURL, err := normalizeAuthURL(loginURL)
	if err != nil {
		return err
	}

	token, err := resolveLoginToken(streams, cfg, opts.TokenStdin)
	if err != nil {
		return err
	}
	account := credentialAccountForURL(loginURL)
	tokenSource := string(config.SourceCredentialStore)

	if err := persistLoginURL(cfg, loginURL); err != nil {
		return err
	}

	switch storeMode {
	case authStoreKeyring:
		store := credentialStoreFactory()
		if store == nil {
			return yerr.New(yerr.CodeConfig, "no credential store available")
		}
		if err := store.Set(credentialService, account, token); err != nil {
			return credentialStoreError("store token", err)
		}
	case authStoreConfig:
		if store := credentialStoreFactory(); store != nil {
			_ = store.Delete(credentialService, account)
		}
		existing, err := readExistingFile(cfg.ConfigPath)
		if err != nil {
			return err
		}
		updated, err := config.SetValue(existing, config.KeyToken, token)
		if err != nil {
			return err
		}
		if err := config.WriteFile(cfg.ConfigPath, updated); err != nil {
			return err
		}
		tokenSource = string(config.SourceFile)
	}

	doc := authLoginDoc{
		URL:        loginURL,
		ConfigPath: cfg.ConfigPath,
		Token:      authTokenDoc{Set: true, Source: tokenSource, Account: account},
		Verified:   false,
	}
	if !opts.SkipVerify {
		identity, err := verifyAuthIdentity(ctx, loginURL, token, opts.Build)
		if err != nil {
			err = redactErrorWithSecret(err, token)
			if tokenSource == string(config.SourceCredentialStore) {
				if store := credentialStoreFactory(); store != nil {
					_ = store.Delete(credentialService, account)
				}
			} else if tokenSource == string(config.SourceFile) {
				_ = clearConfigToken(cfg.ConfigPath)
			}
			return err
		}
		doc.User = identity.User
		doc.ActiveOrganizationID = identity.ActiveOrganizationID
		doc.Verified = true
	}

	if r.JSON() {
		return r.Data(doc)
	}
	if doc.Verified {
		renderWhoamiHuman(r, doc)
	}
	r.Human("URL saved to " + cfg.ConfigPath)
	if tokenSource == string(config.SourceCredentialStore) {
		r.Human("Token stored in OS credential store")
	} else {
		r.Human("Token stored in yalla config")
	}
	return nil
}

func runAuthLogout(r *output.Renderer, cfg *config.Config, rawURL string) error {
	targetURL := strings.TrimSpace(rawURL)
	if targetURL == "" {
		targetURL = cfg.BaseURL
	}
	if targetURL == "" {
		return yerr.New(yerr.CodeConfig, "auth logout requires a URL").
			WithHint("run `yalla auth logout --url <url>` or configure a URL first")
	}
	targetURL, err := normalizeAuthURL(targetURL)
	if err != nil {
		return err
	}
	account := credentialAccountForURL(targetURL)
	fileRemoved := false
	if cfg.TokenSource == config.SourceFile && cfg.ConfigPath != "" {
		if err := clearConfigToken(cfg.ConfigPath); err != nil {
			return err
		}
		fileRemoved = true
	}
	store := credentialStoreFactory()
	keyringRemoved := false
	if store == nil {
		if !fileRemoved {
			return yerr.New(yerr.CodeConfig, "no credential store available")
		}
	} else {
		err = store.Delete(credentialService, account)
		switch {
		case err == nil:
			keyringRemoved = true
		case credentials.IsNotFound(err):
		case !fileRemoved:
			return credentialStoreError("delete token", err)
		}
	}
	tokenSource := string(config.SourceCredentialStore)
	if cfg.TokenSource == config.SourceFile {
		tokenSource = string(config.SourceFile)
	}
	doc := authLogoutDoc{
		URL:     targetURL,
		Token:   authTokenDoc{Set: false, Source: tokenSource, Account: account},
		Removed: keyringRemoved || fileRemoved,
	}
	if r.JSON() {
		return r.Data(doc)
	}
	if doc.Removed {
		r.Human("removed token for " + targetURL)
	} else {
		r.Human("no token found for " + targetURL)
	}
	return nil
}

// runAuthStatus assembles the status payload. It never reports the literal
// token value — only its presence and source — so even a buggy renderer
// downstream cannot leak it. `ready` is the boolean an agent should switch
// on; `reason` carries the human-readable classification when ready=false.
func runAuthStatus(r *output.Renderer, cfg *config.Config) error {
	doc := authStatusDoc{
		BaseURL: fieldDoc{
			Set:    cfg.HasBaseURL(),
			Source: cfg.BaseURLSource,
			Value:  cfg.BaseURL,
		},
		Token: fieldDoc{
			Set:    cfg.HasToken(),
			Source: cfg.TokenSource,
			// Value intentionally omitted — never echo the token.
		},
		ConfigPath: fieldDoc{
			Set:    cfg.ConfigPath != "",
			Source: cfg.ConfigPathSource,
			Value:  cfg.ConfigPath,
		},
		NoInput: cfg.NoInput,
		Output:  string(cfg.Output),
		Ready:   cfg.Ready() == nil,
	}
	if !doc.Ready {
		if err := cfg.Ready(); err != nil {
			var typed *yerr.Error
			if stderrors.As(err, &typed) {
				doc.Reason = string(typed.Code) + ": " + typed.Message
			} else {
				doc.Reason = err.Error()
			}
		}
	}

	if r.JSON() {
		return r.Data(doc)
	}

	var sb strings.Builder
	headers := []string{"FIELD", "STATUS", "SOURCE"}
	rows := [][]string{
		{"base_url", baseURLDisplay(cfg), string(cfg.BaseURLSource)},
		{"token", tokenStatus(cfg), string(cfg.TokenSource)},
		{"config_path", cfg.ConfigPath, string(cfg.ConfigPathSource)},
		{"no_input", boolDisplay(cfg.NoInput), string(cfg.NoInputSource)},
		{"output", string(cfg.Output), string(cfg.OutputSource)},
	}
	if err := output.Table(&sb, headers, rows); err != nil {
		return yerr.Newf(yerr.CodeInternal, "render auth table: %v", err)
	}
	if doc.Ready {
		sb.WriteString("ready: yes\n")
	} else {
		sb.WriteString("ready: no")
		if doc.Reason != "" {
			sb.WriteString(" (")
			sb.WriteString(doc.Reason)
			sb.WriteByte(')')
		}
		sb.WriteByte('\n')
	}
	r.Human(strings.TrimRight(sb.String(), "\n"))
	return nil
}

func resolveLoginToken(streams IOStreams, cfg *config.Config, tokenStdin bool) (string, error) {
	if tokenStdin {
		raw, err := io.ReadAll(streams.In)
		if err != nil {
			return "", yerr.Newf(yerr.CodeInvalidInput, "read API token from stdin: %v", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", yerr.New(yerr.CodeInvalidInput, "API token from stdin is empty")
		}
		return token, nil
	}
	if cfg.TokenSource == config.SourceFlag || cfg.TokenSource == config.SourceEnv {
		if token := strings.TrimSpace(cfg.Token); token != "" {
			return token, nil
		}
	}
	if cfg.NoInput {
		return "", yerr.New(yerr.CodeNoInput, "auth login requires an API token").
			WithHint("pipe it with --token-stdin or set YALLA_TOKEN")
	}
	return promptSecret(streams, "API token: ")
}

func promptLine(streams IOStreams, prompt string) (string, error) {
	_, _ = io.WriteString(streams.ErrOut, prompt)
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := streams.In.Read(buf)
		if n > 0 {
			if buf[0] == '\n' || buf[0] == '\r' {
				break
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", yerr.Newf(yerr.CodeInvalidInput, "read prompt input: %v", err)
		}
	}
	value := strings.TrimSpace(sb.String())
	if value == "" {
		return "", yerr.New(yerr.CodeInvalidInput, "input is empty")
	}
	return value, nil
}

func promptSecret(streams IOStreams, prompt string) (string, error) {
	_, _ = io.WriteString(streams.ErrOut, prompt)
	if f, ok := streams.In.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		raw, err := term.ReadPassword(int(f.Fd()))
		_, _ = io.WriteString(streams.ErrOut, "\n")
		if err != nil {
			return "", yerr.Newf(yerr.CodeInvalidInput, "read API token: %v", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", yerr.New(yerr.CodeInvalidInput, "API token is empty")
		}
		return token, nil
	}
	token, err := promptLine(streams, "")
	if err != nil {
		return "", yerr.New(yerr.CodeInvalidInput, "API token is empty")
	}
	return token, nil
}

func persistLoginURL(cfg *config.Config, loginURL string) error {
	if cfg.ConfigPath == "" {
		return yerr.New(yerr.CodeConfig, "no config file path resolvable").
			WithHint("pass --config <path> or set YALLA_CONFIG=<path>")
	}
	existing, err := readExistingFile(cfg.ConfigPath)
	if err != nil {
		return err
	}
	updated, err := config.SetValue(existing, config.KeyBaseURL, loginURL)
	if err != nil {
		return err
	}
	return config.WriteFile(cfg.ConfigPath, updated)
}

func clearConfigToken(path string) error {
	existing, err := readExistingFile(path)
	if err != nil {
		return err
	}
	updated, err := config.SetValue(existing, config.KeyToken, "")
	if err != nil {
		return err
	}
	return config.WriteFile(path, updated)
}

func redactErrorWithSecret(err error, secret string) error {
	if err == nil || strings.TrimSpace(secret) == "" {
		return err
	}
	typed := yerr.From(err)
	redactor := output.NewRedactor(secret)
	redacted := *typed
	redacted.Message = redactor.Redact(redacted.Message)
	redacted.Hint = redactor.Redact(redacted.Hint)
	return &redacted
}

func verifyAuthIdentity(ctx context.Context, baseURL, token string, build BuildInfo) (authIdentity, error) {
	if strings.TrimSpace(baseURL) == "" {
		return authIdentity{}, yerr.New(yerr.CodeConfig, "no URL configured").
			WithHint("run `yalla auth login --url <url>`")
	}
	if strings.TrimSpace(token) == "" {
		return authIdentity{}, yerr.New(yerr.CodeAuth, "no API token configured").
			WithHint("run `yalla auth login`")
	}
	cli, err := api.NewClient(api.ClientConfig{
		BaseURL:    baseURL,
		Token:      token,
		AuthScheme: api.AuthSchemeBearer,
		UserAgent:  "yalla/" + build.Version,
		MaxRetries: 2,
	})
	if err != nil {
		return authIdentity{}, err
	}
	result, err := cli.Do(ctx, &api.Request{
		Method:     http.MethodGet,
		Path:       "/v1/me",
		Idempotent: true,
	})
	if err != nil {
		return authIdentity{}, err
	}
	if !result.Success() {
		return authIdentity{}, result.AsError()
	}
	return parseAuthIdentity(unwrapYallaData(result.Body)), nil
}

func parseAuthIdentity(body []byte) authIdentity {
	var raw struct {
		ID                   string `json:"id"`
		UserID               string `json:"userId"`
		Email                string `json:"email"`
		Name                 string `json:"name"`
		PrincipalID          string `json:"principal_id"`
		Kind                 string `json:"kind"`
		OrganizationID       string `json:"organization_id"`
		ActiveOrganizationID string `json:"activeOrganizationId"`
	}
	_ = json.Unmarshal(body, &raw)
	id := raw.ID
	if id == "" {
		id = raw.UserID
	}
	if id == "" {
		id = raw.PrincipalID
	}
	orgID := raw.ActiveOrganizationID
	if orgID == "" {
		orgID = raw.OrganizationID
	}
	return authIdentity{
		User: authUserDoc{
			ID:    id,
			Email: raw.Email,
			Name:  raw.Name,
		},
		ActiveOrganizationID: orgID,
	}
}

func renderWhoamiHuman(r *output.Renderer, doc authLoginDoc) {
	switch {
	case doc.User.Email != "":
		r.Human("Authenticated as " + doc.User.Email)
	case doc.User.ID != "":
		r.Human("Authenticated as " + doc.User.ID)
	default:
		r.Human("Authenticated")
	}
	if doc.ActiveOrganizationID != "" {
		r.Human("Active organization: " + doc.ActiveOrganizationID)
	}
}

func normalizeAuthURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", yerr.Newf(yerr.CodeConfig, "invalid URL %q: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", yerr.Newf(yerr.CodeConfig, "invalid URL %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return "", yerr.Newf(yerr.CodeConfig, "invalid URL %q: missing host", raw)
	}
	u.RawQuery = ""
	u.Fragment = ""
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String(), nil
}

func credentialAccountForURL(raw string) string {
	normalized, err := normalizeAuthURL(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return normalized
}

func credentialStoreError(action string, err error) error {
	if credentials.IsUnsupported(err) {
		return yerr.Newf(yerr.CodeUnsupported, "credential store is not supported on this platform").
			WithHint("use YALLA_TOKEN for this session or rerun auth login with --store config if plaintext config is acceptable")
	}
	return yerr.Newf(yerr.CodeConfig, "%s in credential store: %v", action, err).
		WithHint("use YALLA_TOKEN for this session or rerun auth login with --store config if plaintext config is acceptable")
}

func baseURLDisplay(cfg *config.Config) string {
	if !cfg.HasBaseURL() {
		return "(not set)"
	}
	return cfg.BaseURL
}

func tokenStatus(cfg *config.Config) string {
	if cfg.HasToken() {
		return "configured"
	}
	return "not set"
}

func boolDisplay(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
