package encrypt

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testThumbprint = "afa43c43975fbfc700f051fd62016e1571e7e025"

func TestCryptcpEncryptWrapperThumbprintArgv(t *testing.T) {
	t.Parallel()
	cryptcp, argvLog := fakeCryptcp(t)
	out := runWrapper(t, filepath.Join(scriptsDir(t), "cryptcp-encrypt"), []string{testThumbprint}, []string{
		"CRYPTCP=" + cryptcp,
		"CRYPTCP_ARGV_LOG=" + argvLog,
	}, "plain")
	assert.Equal(t, "plain", out)
	assert.Equal(t, []string{"-encr", "-der", "-thumbprint", testThumbprint}, cryptcpFlags(t, argvLog))
}

func TestCryptcpDecryptWrapperPinAndNochain(t *testing.T) {
	t.Parallel()
	cryptcp, argvLog := fakeCryptcp(t)
	out := runWrapper(t, filepath.Join(scriptsDir(t), "cryptcp-decrypt"), []string{testThumbprint}, []string{
		"CRYPTCP=" + cryptcp,
		"CRYPTCP_ARGV_LOG=" + argvLog,
		"CRYPTOPRO_PIN=AitahV7i",
	}, "cipher")
	assert.Equal(t, "cipher", out)
	assert.Equal(t, []string{"-decr", "-nochain", "-thumbprint", testThumbprint, "-pin", "AitahV7i"}, cryptcpFlags(t, argvLog))
}

func TestCryptcpDecryptWrapperOmitsPinWhenUnset(t *testing.T) {
	t.Parallel()
	cryptcp, argvLog := fakeCryptcp(t)
	out := runWrapper(t, filepath.Join(scriptsDir(t), "cryptcp-decrypt"), nil, []string{
		"CRYPTCP=" + cryptcp,
		"CRYPTCP_ARGV_LOG=" + argvLog,
		"CRYPTOPRO_THUMBPRINT=" + testThumbprint,
	}, "cipher")
	assert.Equal(t, "cipher", out)
	assert.Equal(t, []string{"-decr", "-nochain", "-thumbprint", testThumbprint}, cryptcpFlags(t, argvLog))
}

func TestCryptcpEncryptWrapperNormalizesThumbprint(t *testing.T) {
	t.Parallel()
	cryptcp, argvLog := fakeCryptcp(t)
	out := runWrapper(t, filepath.Join(scriptsDir(t), "cryptcp-encrypt"), nil, []string{
		"CRYPTCP=" + cryptcp,
		"CRYPTCP_ARGV_LOG=" + argvLog,
		"CRYPTOPRO_THUMBPRINT=af a4:3c43 975fbfc700f051fd62016e1571e7e025",
	}, "plain")
	assert.Equal(t, "plain", out)
	assert.Equal(t, []string{"-encr", "-der", "-thumbprint", testThumbprint}, cryptcpFlags(t, argvLog))
}

func TestCryptcpDecryptEnvOverridesArgv(t *testing.T) {
	t.Parallel()
	cryptcp, argvLog := fakeCryptcp(t)
	stale := "0000000000000000000000000000000000000000"
	out := runWrapper(t, filepath.Join(scriptsDir(t), "cryptcp-decrypt"), []string{stale}, []string{
		"CRYPTCP=" + cryptcp,
		"CRYPTCP_ARGV_LOG=" + argvLog,
		"CRYPTOPRO_THUMBPRINT=" + testThumbprint,
	}, "cipher")
	assert.Equal(t, "cipher", out)
	assert.Equal(t, []string{"-decr", "-nochain", "-thumbprint", testThumbprint}, cryptcpFlags(t, argvLog))
}

func runWrapper(t *testing.T, script string, args, extraEnv []string, stdin string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), script, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "TMPDIR=" + t.TempDir()}, extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), stderr.String())
	return stdout.String()
}

func scriptsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "scripts"))
}

func fakeCryptcp(t *testing.T) (bin, argvLog string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "cryptcp")
	argvLog = filepath.Join(dir, "argv")
	script := `#!/bin/sh
set -eu
: > "$CRYPTCP_ARGV_LOG"
n=$#
i=0
in=""
out=""
for a in "$@"; do
	i=$((i + 1))
	if [ "$i" -eq $((n - 1)) ]; then
		in=$a
		continue
	fi
	if [ "$i" -eq "$n" ]; then
		out=$a
		continue
	fi
	printf '%s\n' "$a" >> "$CRYPTCP_ARGV_LOG"
done
cp "$in" "$out"
`
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o700))
	return bin, argvLog
}

func cryptcpFlags(t *testing.T, argvLog string) []string {
	t.Helper()
	raw, err := os.ReadFile(argvLog)
	require.NoError(t, err)
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
