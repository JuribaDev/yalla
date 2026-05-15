package httpapi

import (
	"context"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// fakeBreakGlassController is the canned BreakGlassController for httpapi
// tests. The zero value returns zero values and no error, which is all the
// public-surface and unrelated-endpoint suites need; the break-glass tests
// set the result fields and read the recorded inputs back to prove the
// handler forwards path parameters and decoded request bodies to the store
// layer unchanged.
type fakeBreakGlassController struct {
	startResult  store.BreakGlassSession
	startErr     error
	startGot     *store.StartBreakGlassInput
	revokeResult store.BreakGlassSession
	revokeErr    error
	revokeGot    *store.RevokeBreakGlassInput
	listResult   []store.BreakGlassSession
	listErr      error
	listGotOrg   *string
	listGotLimit *int
	getResult    store.BreakGlassSession
	getErr       error
	getGotOrg    *string
	getGotID     *string
}

func (f fakeBreakGlassController) StartSession(_ context.Context, in store.StartBreakGlassInput) (store.BreakGlassSession, error) {
	if f.startGot != nil {
		*f.startGot = in
	}
	if f.startErr != nil {
		return store.BreakGlassSession{}, f.startErr
	}
	return f.startResult, nil
}

func (f fakeBreakGlassController) Revoke(_ context.Context, in store.RevokeBreakGlassInput) (store.BreakGlassSession, error) {
	if f.revokeGot != nil {
		*f.revokeGot = in
	}
	if f.revokeErr != nil {
		return store.BreakGlassSession{}, f.revokeErr
	}
	return f.revokeResult, nil
}

func (f fakeBreakGlassController) ListSessions(_ context.Context, organizationID string, limit int) ([]store.BreakGlassSession, error) {
	if f.listGotOrg != nil {
		*f.listGotOrg = organizationID
	}
	if f.listGotLimit != nil {
		*f.listGotLimit = limit
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResult, nil
}

func (f fakeBreakGlassController) GetSession(_ context.Context, organizationID, sessionID string) (store.BreakGlassSession, error) {
	if f.getGotOrg != nil {
		*f.getGotOrg = organizationID
	}
	if f.getGotID != nil {
		*f.getGotID = sessionID
	}
	if f.getErr != nil {
		return store.BreakGlassSession{}, f.getErr
	}
	return f.getResult, nil
}
