package encrypt

import (
	"fmt"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

// New selects an Encryptor implementation from config.
func New(cfg config.EncryptionConfig) (port.Encryptor, error) {
	switch cfg.Mode {
	case "", NameNone:
		return Passthrough{}, nil
	case NameNative:
		return NewNative(cfg.Native)
	case NameCommand:
		return NewCommand(cfg.Command)
	default:
		return nil, fmt.Errorf("unknown encryption mode %q", cfg.Mode)
	}
}
