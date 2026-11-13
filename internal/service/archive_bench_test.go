package service_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/service"
)

// BenchmarkArchiveUpload measures the archive write path, which hashes the
// plaintext once for identity and once more while streaming to prove the
// committed bytes still match the header (problems.md D8).
func BenchmarkArchiveUpload(b *testing.B) {
	root := b.TempDir()

	payload := make([]byte, 4<<20)
	for i := range payload {
		payload[i] = byte(i * 17)
	}

	p := filepath.Join(root, "a.bin")
	require.NoError(b, os.WriteFile(p, payload, 0o600))

	info := domain.FileInfo{
		AbsPath: p,
		RelPath: "a.bin",
		Size:    int64(len(payload)),
	}

	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		store := newMemStore()
		svc := service.NewArchive(
			scanner.New(scanner.Options{}),
			keying.Mapper{},
			store,
			encrypt.Passthrough{},
			nil,
		)

		if _, _, err := svc.UploadFile(ctx, info, service.ArchiveOptions{Root: root}); err != nil {
			b.Fatal(err)
		}
	}
}
