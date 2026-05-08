package output

// SuccessSchema is the stable schema_version embedded in every success JSON
// envelope. Bumping this constant is a public-API change.
const SuccessSchema = "yalla.output.v1"

// successEnvelope is the wire representation of a --json success response.
// The struct is unexported so callers cannot accidentally hand-roll envelopes
// outside this package.
type successEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Data          any    `json:"data"`
}

// errorEnvelope is the wire representation of a --json error response.
type errorEnvelope struct {
	SchemaVersion string       `json:"schema_version"`
	Error         errorPayload `json:"error"`
}

// errorPayload is the inner error block. Hint is omitempty because not every
// failure has a useful remediation suggestion, and emitting an empty string
// would corrupt agents that switch on hint != null.
type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}
