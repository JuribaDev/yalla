package store

import "strings"

func auditEventActorKind(raw string) string {
	switch strings.TrimSpace(raw) {
	case "user":
		return "usr"
	case "service_account":
		return "sa"
	case "api_key", "worker":
		return "system"
	default:
		return strings.TrimSpace(raw)
	}
}
