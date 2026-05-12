// Package credentials wraps the host operating system's secure credential
// store behind a tiny interface the CLI can fake in tests.
package credentials

import (
	stderrors "errors"

	"github.com/zalando/go-keyring"
)

// Store is the minimum credential-store surface yalla needs.
type Store interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// KeyringStore stores secrets in the platform credential manager exposed by
// github.com/zalando/go-keyring: macOS Keychain, Windows Credential Manager,
// and Secret Service-compatible Linux keyrings.
type KeyringStore struct{}

func (KeyringStore) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (KeyringStore) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}

func (KeyringStore) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

// IsNotFound reports whether err means the requested secret does not exist.
func IsNotFound(err error) bool {
	return stderrors.Is(err, keyring.ErrNotFound)
}

// IsUnsupported reports whether the current platform or session has no
// usable credential-store backend.
func IsUnsupported(err error) bool {
	return stderrors.Is(err, keyring.ErrUnsupportedPlatform)
}
