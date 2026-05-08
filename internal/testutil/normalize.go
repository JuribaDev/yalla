package testutil

import "regexp"

// Normalizer is a transform applied to a string before golden comparison.
// Reusable normalisers in this file cover the dynamic fields that vary
// between runs (request ids, durations, timestamps); story-specific ones
// can be composed inline.
type Normalizer = func(string) string

// reISO8601Timestamp matches the timestamp shape we emit (RFC3339 with
// optional fractional seconds and either Z or a numeric offset). It is
// deliberately strict to avoid false positives in unrelated text.
var reISO8601Timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)

// reJSONRequestID matches "request_id":"..." pairs in JSON output. The
// value can be any non-quote run; the entire pair is replaced so the
// surrounding JSON stays well-formed.
var reJSONRequestID = regexp.MustCompile(`"request_id"\s*:\s*"[^"]*"`)

// reJSONTraceID matches "trace_id":"..." pairs.
var reJSONTraceID = regexp.MustCompile(`"trace_id"\s*:\s*"[^"]*"`)

// reJSONDurationMs matches "duration_ms": <number>. Both integers and
// floats land in goldens depending on Go's encoder; the regex accepts both.
var reJSONDurationMs = regexp.MustCompile(`"duration_ms"\s*:\s*-?\d+(\.\d+)?`)

// reJSONStartedFinishedAt matches the two timestamp fields the api executor
// emits in dry-run and execution envelopes.
var reJSONStartedFinishedAt = regexp.MustCompile(`"(started_at|finished_at)"\s*:\s*"[^"]*"`)

// NormalizeRequestID rewrites every "request_id":"..." JSON pair so dynamic
// header values do not destabilise goldens. Use it for any envelope that
// surfaces upstream observability headers.
func NormalizeRequestID(raw string) string {
	return reJSONRequestID.ReplaceAllString(raw, `"request_id":"[REQUEST_ID]"`)
}

// NormalizeTraceID rewrites every "trace_id":"..." JSON pair.
func NormalizeTraceID(raw string) string {
	return reJSONTraceID.ReplaceAllString(raw, `"trace_id":"[TRACE_ID]"`)
}

// NormalizeDuration rewrites "duration_ms": N into a stable placeholder.
func NormalizeDuration(raw string) string {
	return reJSONDurationMs.ReplaceAllString(raw, `"duration_ms":0`)
}

// NormalizeTimestamps rewrites "started_at" / "finished_at" JSON pairs and
// any free-floating ISO 8601 timestamp into stable placeholders. The two
// passes are independent so a JSON envelope and a human banner can both be
// stripped with a single normaliser.
func NormalizeTimestamps(raw string) string {
	out := reJSONStartedFinishedAt.ReplaceAllString(raw, `"$1":"[TIMESTAMP]"`)
	out = reISO8601Timestamp.ReplaceAllString(out, `[TIMESTAMP]`)
	return out
}

// ChainNormalizers runs the supplied normalisers left-to-right, returning a
// single composite function. It is sugar for callers that want to feed a
// curated stack into Golden's options without inlining a loop.
func ChainNormalizers(fns ...Normalizer) Normalizer {
	return func(raw string) string {
		for _, fn := range fns {
			raw = fn(raw)
		}
		return raw
	}
}

// DefaultJSONNormalizers is the recommended pre-set for golden comparisons
// of any JSON envelope produced by yalla. It strips request/trace ids,
// duration_ms, and timestamps so the remainder is fully deterministic.
func DefaultJSONNormalizers() []Normalizer {
	return []Normalizer{
		NormalizeRequestID,
		NormalizeTraceID,
		NormalizeDuration,
		NormalizeTimestamps,
	}
}
