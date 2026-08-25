package remote

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/port"
)

const headerMTime = "X-S3Vault-Mtime"

// Client PUTs plaintext files to a remote s3vault server.
type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	limiter *Limiter
}

var _ port.RemoteIngest = (*Client)(nil)

// Options configure a remote ingest client.
type Options struct {
	BaseURL      string
	Token        string
	RateLimitBPS int64
	HTTPClient   *http.Client
}

// New validates BaseURL and builds a Client.
func New(opts Options) (*Client, error) {
	raw := strings.TrimSpace(opts.BaseURL)
	if raw == "" {
		return nil, fmt.Errorf("remote.url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("remote.url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("remote.url: scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("remote.url: host is required")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 0} // large uploads; cancel via context
	}
	return &Client{
		base:    u,
		token:   opts.Token,
		http:    hc,
		limiter: NewLimiter(opts.RateLimitBPS),
	}, nil
}

// PutFile streams the local file to PUT /files/{requestPath}.
// Status mapping: 201 → upload, 200 → skip (identical), 204 → omit (policy skip), 409 → fail, else error.
func (c *Client) PutFile(ctx context.Context, requestPath string, info domain.FileInfo) (identity.Action, error) {
	requestPath = strings.Trim(strings.ReplaceAll(requestPath, "\\", "/"), "/")
	if requestPath == "" {
		return identity.ActionUnknown, fmt.Errorf("%w: empty request path", domain.ErrInvalidPath)
	}
	f, err := os.Open(info.AbsPath)
	if err != nil {
		return identity.ActionUnknown, err
	}
	defer f.Close()

	body := c.limiter.Reader(ctx, f)
	endpoint := *c.base
	endpoint.Path = "/" + strings.Trim(path.Join(strings.Trim(c.base.Path, "/"), "files", requestPath), "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), body)
	if err != nil {
		return identity.ActionUnknown, err
	}
	req.ContentLength = info.Size
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if !info.ModTime.IsZero() {
		req.Header.Set(headerMTime, info.ModTime.UTC().Format(time.RFC3339Nano))
	}

	res, err := c.http.Do(req)
	if err != nil {
		return identity.ActionUnknown, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))

	switch res.StatusCode {
	case http.StatusCreated:
		return identity.ActionUpload, nil
	case http.StatusOK:
		return identity.ActionSkip, nil
	case http.StatusNoContent:
		return identity.ActionOmit, nil
	case http.StatusConflict:
		return identity.ActionFail, fmt.Errorf("object exists with different checksum: %s", requestPath)
	case http.StatusUnauthorized:
		return identity.ActionUnknown, fmt.Errorf("remote unauthorized")
	default:
		return identity.ActionUnknown, fmt.Errorf("remote put %s: status %d", requestPath, res.StatusCode)
	}
}
