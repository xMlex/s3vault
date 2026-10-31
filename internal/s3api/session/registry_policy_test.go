package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryUserPolicy(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	s, err := reg.CreateForUser("AKIA", 7, "dir/file", "tenant-a", "fp", "target-fp", "root/tenant-a/dir/file")
	require.NoError(t, err)

	got, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-a/dir/file", 7, "tenant-a", "fp", "target-fp")
	require.NoError(t, err)
	assert.Same(t, s, got)

	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "access key", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "OTHER", "dir/file", "root/tenant-a/dir/file", 7, "tenant-a", "fp", "target-fp")
			return err
		}},
		{name: "client key", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "other", "root/tenant-a/dir/file", 7, "tenant-a", "fp", "target-fp")
			return err
		}},
		{name: "backend key", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-b/dir/file", 7, "tenant-a", "fp", "target-fp")
			return err
		}},
		{name: "user", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-a/dir/file", 8, "tenant-a", "fp", "target-fp")
			return err
		}},
		{name: "prefix", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-a/dir/file", 7, "tenant-b", "fp", "target-fp")
			return err
		}},
		{name: "profile", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-a/dir/file", 7, "tenant-a", "other", "target-fp")
			return err
		}},
		{name: "target", fn: func() error {
			_, err := reg.GetForWrite(s.UploadID, "AKIA", "dir/file", "root/tenant-a/dir/file", 7, "tenant-a", "fp", "other-target")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, tt.fn(), ErrForeignUpload)
		})
	}

	// Abort/ListParts are bound only to the access key and client key; a policy
	// change must not strand the upload.
	got, err = reg.GetForOwner(s.UploadID, "AKIA", "dir/file")
	require.NoError(t, err)
	assert.Same(t, s, got)

	_, err = reg.GetForOwner(s.UploadID, "AKIA", "other")
	assert.ErrorIs(t, err, ErrForeignUpload)
}
