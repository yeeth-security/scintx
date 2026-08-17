package providers

import "github.com/yeeth-security/scintx/internal/scintx"

func RandID() string {
	return scintx.RandHex()
}