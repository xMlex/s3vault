package localstore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/storetest"
)

func TestConformance(t *testing.T) {
	t.Parallel()
	storetest.RunConformance(t, func(t *testing.T) (port.ObjectStore, string) {
		st, err := localstore.New(config.LocalConfig{Dir: t.TempDir()})
		require.NoError(t, err)
		t.Cleanup(func() { _ = st.Close() })
		return st, ""
	})
}
