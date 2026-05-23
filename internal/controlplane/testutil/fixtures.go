package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// Service kinds mirror Dokploy's service taxonomy. They are plain strings so
// fixtures stay decoupled from the (not-yet-built) domain enum; the repository
// layer is responsible for validating them on persist.
const (
	ServiceKindApplication = "application"
	ServiceKindDatabase    = "database"
	ServiceKindCompose     = "compose"
)

// Organization is an in-memory test fixture for a Yalla organization — the
// tenant root of the hierarchy.
type Organization struct {
	ID   string
	Slug string
	Name string
}

// User is an in-memory test fixture for a member of an Organization.
type User struct {
	ID             string
	OrganizationID string
	Email          string
	Name           string
}

// ServiceAccount is an in-memory test fixture for a non-human principal — a
// CI/automation identity scoped to a single Organization. Service accounts own
// API keys but are never human users.
type ServiceAccount struct {
	ID             string
	OrganizationID string
	Slug           string
	Name           string
}

// APIKey is an in-memory test fixture for an organization-scoped API key.
// Secret is a fake plaintext credential; it exists so redaction tests have a
// realistic value to assert against and must never be logged or rendered.
type APIKey struct {
	ID             string
	OrganizationID string
	UserID         string
	Prefix         string
	Secret         string
	Name           string
}

// Project is an in-memory test fixture for a project within an Organization.
type Project struct {
	ID             string
	OrganizationID string
	Slug           string
	Name           string
}

// Environment is an in-memory test fixture for an environment within a Project.
type Environment struct {
	ID             string
	ProjectID      string
	OrganizationID string
	Slug           string
	Name           string
}

// Service is an in-memory test fixture for a service within an Environment.
type Service struct {
	ID             string
	EnvironmentID  string
	ProjectID      string
	OrganizationID string
	Slug           string
	Name           string
	Kind           string
}

// Factory builds deterministically-shaped, globally-unique persistence
// fixtures. Each Factory holds its own random namespace token, so fixtures
// produced by two factories — i.e. two different tests — never collide on an
// ID, slug, email, or key secret. That is the data-shape half of the "a test
// can never observe another test's tenant" guarantee; the database half is
// provided by RequireDB / RequireMigratedDB.
//
// A Factory builds in-memory values only. Persisting them is the job of the
// repository layer; the typed fixture structs here are the shared shape every
// persistence test seeds from. Factory is safe for concurrent use.
type Factory struct {
	token string
	seq   atomic.Uint64
}

// NewFactory returns a Factory with a fresh random namespace token.
func NewFactory(t testing.TB) *Factory {
	t.Helper()
	return &Factory{token: randomToken(t)}
}

// Organization builds a new Organization fixture. An empty label falls back to
// a generated default name.
func (f *Factory) Organization(label string) Organization {
	n := f.next()
	return Organization{
		ID:   f.id("org", n),
		Slug: f.slug(label, "org", n),
		Name: displayName(label, "Organization", n),
	}
}

// User builds a new User fixture linked to org.
func (f *Factory) User(org Organization, label string) User {
	n := f.next()
	return User{
		ID:             f.id("usr", n),
		OrganizationID: org.ID,
		Email:          fmt.Sprintf("%s-%s%d@fixtures.yalla.test", localPart(label, "user"), f.token, n),
		Name:           displayName(label, "User", n),
	}
}

// ServiceAccount builds a new ServiceAccount fixture linked to org.
func (f *Factory) ServiceAccount(org Organization, label string) ServiceAccount {
	n := f.next()
	return ServiceAccount{
		ID:             f.id("sa", n),
		OrganizationID: org.ID,
		Slug:           f.slug(label, "service-account", n),
		Name:           displayName(label, "Service Account", n),
	}
}

// APIKey builds a new APIKey fixture linked to org and user. The returned
// Secret is a fake plaintext credential for redaction tests.
func (f *Factory) APIKey(org Organization, user User, label string) APIKey {
	n := f.next()
	return APIKey{
		ID:             f.id("key", n),
		OrganizationID: org.ID,
		UserID:         user.ID,
		Prefix:         "yk_" + f.token[:8],
		Secret:         fmt.Sprintf("sk_test_%s%016x", f.token, n),
		Name:           displayName(label, "API Key", n),
	}
}

// Project builds a new Project fixture linked to org.
func (f *Factory) Project(org Organization, label string) Project {
	n := f.next()
	return Project{
		ID:             f.id("prj", n),
		OrganizationID: org.ID,
		Slug:           f.slug(label, "project", n),
		Name:           displayName(label, "Project", n),
	}
}

// Environment builds a new Environment fixture linked to proj (and, through it,
// to the owning organization).
func (f *Factory) Environment(proj Project, label string) Environment {
	n := f.next()
	return Environment{
		ID:             f.id("env", n),
		ProjectID:      proj.ID,
		OrganizationID: proj.OrganizationID,
		Slug:           f.slug(label, "env", n),
		Name:           displayName(label, "Environment", n),
	}
}

// Service builds a new Service fixture linked to env (and, through it, to the
// owning project and organization). Kind defaults to ServiceKindApplication;
// callers that need another kind set Service.Kind on the returned value.
func (f *Factory) Service(env Environment, label string) Service {
	n := f.next()
	return Service{
		ID:             f.id("svc", n),
		EnvironmentID:  env.ID,
		ProjectID:      env.ProjectID,
		OrganizationID: env.OrganizationID,
		Slug:           f.slug(label, "service", n),
		Name:           displayName(label, "Service", n),
		Kind:           ServiceKindApplication,
	}
}

// next returns the next per-factory sequence number. It is concurrency-safe.
func (f *Factory) next() uint64 { return f.seq.Add(1) }

// id builds a globally-unique identifier of the form "<kind>_<token><seq>".
func (f *Factory) id(kind string, n uint64) string {
	return fmt.Sprintf("%s_%s%04d", kind, f.token, n)
}

// slug builds a globally-unique slug from a human label, falling back to
// fallback when the label has no slug-safe characters.
func (f *Factory) slug(label, fallback string, n uint64) string {
	base := slugify(label)
	if base == "" {
		base = fallback
	}
	return fmt.Sprintf("%s-%s-%d", base, f.token, n)
}

// localPart builds a slug-safe email local-part prefix.
func localPart(label, fallback string) string {
	base := slugify(label)
	if base == "" {
		return fallback
	}
	return base
}

// slugify lowercases s and collapses every run of non-alphanumeric characters
// into a single dash, trimming leading/trailing dashes.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dashPending := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if dashPending && b.Len() > 0 {
				b.WriteByte('-')
			}
			dashPending = false
			b.WriteRune(r)
		default:
			dashPending = true
		}
	}
	return b.String()
}

// displayName returns the trimmed label, or "<fallback> <n>" when it is empty.
func displayName(label, fallback string, n uint64) string {
	if label = strings.TrimSpace(label); label != "" {
		return label
	}
	return fmt.Sprintf("%s %d", fallback, n)
}

// randomToken returns a 16-hex-character random namespace token.
func randomToken(t testing.TB) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("testutil: generate factory token: %v", err)
	}
	return hex.EncodeToString(buf[:])
}
