package credentials

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// getFromKeyring returns the token for provider, or false if missing.
func getFromKeyring(provider string) (string, bool, error) {
	secret, err := keyring.Get(keyringService, provider)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	if secret == "" {
		return "", false, nil
	}
	return secret, true, nil
}

// setInKeyring stores the token in the OS keychain.
func setInKeyring(provider, token string) error {
	return keyring.Set(keyringService, provider, token)
}

// deleteFromKeyring removes the token; missing entry is OK.
func deleteFromKeyring(provider string) error {
	err := keyring.Delete(keyringService, provider)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}
