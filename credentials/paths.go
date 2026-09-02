package credentials

import (
	"os"
	"path/filepath"
)

const (
	// keyringService is the OS keychain application name.
	keyringService = "scintx"
	// credentialsFileName is the YAML file under the config directory.
	credentialsFileName = "credentials"
)

// ConfigDir returns the directory for scintx config and credential files.
// Override with SCINTX_CONFIG_DIR (tests and unusual layouts).
func ConfigDir() (string, error) {
	if v := os.Getenv("SCINTX_CONFIG_DIR"); v != "" {
		return v, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "scintx"), nil
}

// CredentialsPath is the YAML fallback file (mode 0600 when written).
func CredentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, credentialsFileName), nil
}
