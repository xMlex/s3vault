//go:build linux

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
	v.ChangeTime = time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
	v.Inode = st.Ino
	v.Device = st.Dev
}
