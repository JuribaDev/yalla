package credentials_test

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/JuribaDev/yalla/internal/credentials"
)

// The KeyringStore type is a thin pass-through to github.com/zalando/go-keyring
// and exercising its Get/Set/Delete methods would hit the host operating
// system's real credential store — non-deterministic and platform-specific.
// What we CAN deterministically pin is the package's two error-classification
// helpers. They are the surface every caller uses to branch on missing
// credentials vs unsupported platform, so a regression in either (e.g. a
// sentinel rename in the upstream keyring library that we didn't track) must
// fail the build.

func TestIsNotFoundIdentifiesUpstreamErrNotFound(t *testing.T) {
	t.Parallel()

	if !credentials.IsNotFound(keyring.ErrNotFound) {
		t.Fatalf("IsNotFound(keyring.ErrNotFound) = false; the helper MUST treat the upstream ErrNotFound sentinel as not-found so callers can distinguish a missing credential from a real failure.")
	}

	wrapped := errors.New("wrapping keyring not-found: " + keyring.ErrNotFound.Error())
	if credentials.IsNotFound(wrapped) {
		t.Errorf("IsNotFound(plain-text wrap) = true; the helper must use errors.Is, not string matching.")
	}

	if credentials.IsNotFound(nil) {
		t.Errorf("IsNotFound(nil) = true; a nil error is never a not-found.")
	}

	if credentials.IsNotFound(errors.New("some other error")) {
		t.Errorf("IsNotFound(unrelated error) = true; the helper must only match the upstream ErrNotFound sentinel.")
	}
}

func TestIsUnsupportedIdentifiesUpstreamErrUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	if !credentials.IsUnsupported(keyring.ErrUnsupportedPlatform) {
		t.Fatalf("IsUnsupported(keyring.ErrUnsupportedPlatform) = false; the helper MUST treat the upstream ErrUnsupportedPlatform sentinel as unsupported so callers can fall back to file-backed storage.")
	}

	if credentials.IsUnsupported(nil) {
		t.Errorf("IsUnsupported(nil) = true; a nil error is never an unsupported-platform error.")
	}

	if credentials.IsUnsupported(keyring.ErrNotFound) {
		t.Errorf("IsUnsupported(ErrNotFound) = true; the two classifiers must not collapse — callers branch on them separately.")
	}

	if credentials.IsUnsupported(errors.New("some other error")) {
		t.Errorf("IsUnsupported(unrelated error) = true; the helper must only match the upstream ErrUnsupportedPlatform sentinel.")
	}
}

// TestStoreInterfaceIsSatisfiedByKeyringStore is a compile-time pin: if the
// KeyringStore type ever stops satisfying the Store interface (e.g. a method
// signature change), this line fails the build. The runtime assertion costs
// nothing and documents the contract.
func TestStoreInterfaceIsSatisfiedByKeyringStore(t *testing.T) {
	t.Parallel()

	var _ credentials.Store = credentials.KeyringStore{}
}
