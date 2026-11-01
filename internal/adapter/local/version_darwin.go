//go:build darwin

package localstore

import (
	"io/fs"
	"syscall"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
)

func applyFileChangeInfo(fi fs.FileInfo, v *domain.FileVersion) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	v.ChangeTime = time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec)
	v.Inode = st.Ino
	v.Device = uint64(st.Dev)
}
