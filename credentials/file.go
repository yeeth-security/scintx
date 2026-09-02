package credentials

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// fileDocument is the on-disk credentials shape.
type fileDocument struct {
	Providers map[string]ProviderCreds `yaml:"providers"`
}

// loadFile reads the credentials YAML. Missing file is empty, not an error.
func loadFile(path string) (fileDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileDocument{Providers: map[string]ProviderCreds{}}, nil
		}
		return fileDocument{}, err
	}
	var doc fileDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fileDocument{}, fmt.Errorf("parse credentials file: %w", err)
	}
	if doc.Providers == nil {
		doc.Providers = map[string]ProviderCreds{}
	}
	return doc, nil
}

// saveFile writes the credentials YAML with owner-only permissions.
func saveFile(path string, doc fileDocument) error {
	if doc.Providers == nil {
		doc.Providers = map[string]ProviderCreds{}
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// 0600 so other users on the machine cannot read the PAT.
	return os.WriteFile(path, data, 0o600)
}

func getFromFile(provider string) (ProviderCreds, bool, error) {
	path, err := CredentialsPath()
	if err != nil {
		return ProviderCreds{}, false, err
	}
	doc, err := loadFile(path)
	if err != nil {
		return ProviderCreds{}, false, err
	}
	c, ok := doc.Providers[provider]
	if !ok {
		return ProviderCreds{}, false, nil
	}
	// Token empty is still "present" when username-only (keyring holds the secret).
	if c.Token == "" && c.User == "" {
		return ProviderCreds{}, false, nil
	}
	return c, true, nil
}

func setInFile(provider string, c ProviderCreds) error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}
	doc, err := loadFile(path)
	if err != nil {
		return err
	}
	doc.Providers[provider] = c
	return saveFile(path, doc)
}

func deleteFromFile(provider string) error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}
	doc, err := loadFile(path)
	if err != nil {
		return err
	}
	if _, ok := doc.Providers[provider]; !ok {
		return nil
	}
	delete(doc.Providers, provider)
	// Remove empty file so status stays clean.
	if len(doc.Providers) == 0 {
		_ = os.Remove(path)
		return nil
	}
	return saveFile(path, doc)
}
