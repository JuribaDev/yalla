package cli

import (
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

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
// enough for the renderer: --json is bound to its target before
// PersistentPreRunE runs, so an agent that requested JSON output still
// receives a JSON error envelope even on a usage failure.
func renderTerminalError(streams IOStreams, flags *GlobalFlags, err error) int {
	if err == nil {
		return 0
	}
	e := yerr.From(err)
	redactor := output.NewRedactor(flags.Token)
	r := output.New(streams.Out, streams.ErrOut, flags.JSON, redactor)
	_ = r.Error(e)
	return e.ExitCode()
}
