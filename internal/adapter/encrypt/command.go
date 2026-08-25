package encrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

const maxCmdErr = 64 * 1024

// EnvThumbprint is passed to CryptoPro wrappers; decrypt prefers it over argv.
const EnvThumbprint = "CRYPTOPRO_THUMBPRINT"

type thumbprintKey struct{}

// WithCryptoProThumbprint attaches a recipient SHA-1 thumbprint for Decrypt.
// Used so download can use the thumbprint from the S3VCTR01 header.
func WithCryptoProThumbprint(ctx context.Context, thumbprint string) context.Context {
	thumbprint = config.NormalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return ctx
	}
	return context.WithValue(ctx, thumbprintKey{}, thumbprint)
}

// CryptoProThumbprintFrom returns the thumbprint from WithCryptoProThumbprint, if any.
func CryptoProThumbprintFrom(ctx context.Context) string {
	s, _ := ctx.Value(thumbprintKey{}).(string)
	return s
}

// Command runs an external encrypt/decrypt program without a shell.
type Command struct {
	encrypt    []string
	decrypt    []string
	provider   string
	thumbprint string
	timeout    time.Duration
}

var _ port.Encryptor = (*Command)(nil)

// NewCommand validates argv lists.
func NewCommand(cfg config.CommandEnc) (*Command, error) {
	if len(cfg.Encrypt) == 0 || len(cfg.Decrypt) == 0 {
		return nil, fmt.Errorf("encryption.command encrypt and decrypt argv must be set")
	}
	t := cfg.Timeout
	if t <= 0 {
		t = 30 * time.Minute
	}
	tp := config.NormalizeThumbprint(cfg.Thumbprint)
	if tp == "" {
		tp = config.ThumbprintFromArgv(cfg.Encrypt)
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "cryptopro"
	}
	return &Command{
		encrypt:    append([]string(nil), cfg.Encrypt...),
		decrypt:    append([]string(nil), cfg.Decrypt...),
		provider:   provider,
		thumbprint: tp,
		timeout:    t,
	}, nil
}

func (c *Command) Name() string { return "command" }

// Provider is the command encryptor name written into S3VCTR01.
func (c *Command) Provider() string { return c.provider }

// CryptoProThumbprint is the recipient thumbprint for new uploads (S3VCTR01).
func (c *Command) CryptoProThumbprint() string { return c.thumbprint }

func (c *Command) Encrypt(ctx context.Context, dst io.Writer, src io.Reader) error {
	return c.run(ctx, c.encrypt, c.thumbprint, dst, src)
}

func (c *Command) Decrypt(ctx context.Context, dst io.Writer, src io.Reader) error {
	tp := CryptoProThumbprintFrom(ctx)
	if tp == "" {
		tp = c.thumbprint
	}
	return c.run(ctx, c.decrypt, tp, dst, src)
}

func (c *Command) run(ctx context.Context, argv []string, thumbprint string, dst io.Writer, src io.Reader) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv comes from config, never from a shell string
	cmd.Stdin = src
	cmd.Stdout = dst
	errBuf := &limitedBuffer{limit: maxCmdErr}
	cmd.Stderr = errBuf
	cmd.Env = os.Environ()
	if thumbprint != "" {
		cmd.Env = append(cmd.Env, EnvThumbprint+"="+thumbprint)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("encrypt command %s: %w: %s", argv[0], err, errBuf.String())
	}
	return nil
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	remain := l.limit - l.buf.Len()
	if remain <= 0 {
		return len(p), nil
	}
	if len(p) > remain {
		_, _ = l.buf.Write(p[:remain])
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}
