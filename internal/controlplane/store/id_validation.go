package store

import (
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

func hasKindPrefix(id string, kind domain.Kind) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	if strings.HasPrefix(id, kind.String()+"_") {
		return true
	}
	return kind == domain.KindProject && strings.HasPrefix(id, "prj_")
}
