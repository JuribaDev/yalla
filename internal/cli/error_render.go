package cli

import (
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// envSnapshotForRenderer is the parse-time fallback used by the terminal
// error renderer to honour --json mode and token redaction even when cobra
// failed before PersistentPreRunE could resolve the full config. Tests
// override the variable to isolate themselves from the real process
// environment; the package default reads YALLA_OUTPUT and YALLA_TOKEN
// through the standard config loader.
var envSnapshotForRenderer = func() config.EnvSnapshot {
	return config.NewLoader().SnapshotForRenderer()
}

// renderTerminalError converts an error returned by cmd.Execute into a typed
// yalla error, renders it via the output package, and returns the stable
// exit code mapped from the error code.
//
// The renderer is the sole printing point for top-level command failures
// (Cobra's SilenceErrors is set on the root). It honours --json by emitting
// the "yalla.error.v1" envelope on stderr, applies secret redaction so
// --token never leaks into messages or hints, and returns the POSIX-style
// exit code derived from the error's Code so scripts and agents can switch
// on it deterministically.
//
// flags may carry partial values when cobra failed during flag parsing (the
// binding is updated as each flag is parsed). That partial state is good
// enough for the --json flag — it is bound to its target before
// PersistentPreRunE runs. For the env-only path (the agent set
// YALLA_OUTPUT or YALLA_TOKEN but never typed the flag), envSnapshotForRenderer
// supplies the fallback so JSON envelopes and redaction stay honoured even on
// usage failures.
func renderTerminalError(streams IOStreams, flags *GlobalFlags, err error) int {
	if err == nil {
		return 0
	}
	snap := envSnapshotForRenderer()
	isJSON := flags.JSON || snap.Output.IsJSON()
	token := flags.Token
	if token == "" {
		token = snap.Token
	}

	e := yerr.From(err)
	redactor := output.NewRedactor(token)
	r := output.New(streams.Out, streams.ErrOut, isJSON, redactor)
	_ = r.Error(e)
	return e.ExitCode()
}
