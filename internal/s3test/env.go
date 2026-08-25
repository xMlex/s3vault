package s3test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xMlex/s3vault/internal/config"
)

// ConfigFromEnv loads S3 settings from the repo .env and process environment.
func ConfigFromEnv(t *testing.T) config.S3Config {
	t.Helper()
	loadDotEnv(t)

	endpoint := firstEnv("S3VAULT_S3_ENDPOINT")
	bucket := firstEnv("S3VAULT_S3_BUCKET")
	region := firstEnv("S3VAULT_S3_REGION")
	access := firstEnv("S3VAULT_S3_ACCESS_KEY")
	secret := firstEnv("S3VAULT_S3_SECRET_KEY")
	if endpoint == "" || bucket == "" || access == "" || secret == "" {
		t.Skip("S3 env not set (.env with S3VAULT_S3_ENDPOINT, S3VAULT_S3_BUCKET, S3VAULT_S3_ACCESS_KEY, S3VAULT_S3_SECRET_KEY)")
	}
	if region == "" {
		region = "us-east-1"
	}

	pathStyle := true
	if v := firstEnv("S3VAULT_S3_PATH_STYLE"); v != "" {
		pathStyle = v == "true" || v == "1"
	}

	cfg := config.S3Config{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Region:    region,
		Bucket:    bucket,
		Prefix:    firstEnv("S3VAULT_S3_PREFIX"),
		AccessKey: access,
		SecretKey: secret,
		PathStyle: pathStyle,
		TLS:       !strings.HasPrefix(endpoint, "http://"),
	}
	return cfg
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func loadDotEnv(t *testing.T) {
	t.Helper()
	path := findDotEnv()
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open .env: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if os.Getenv(k) == "" {
			t.Setenv(k, v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read .env: %v", err)
	}
}

func findDotEnv() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for range 8 {
		p := filepath.Join(wd, ".env")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	return ""
}
