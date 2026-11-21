//go:build bigtest

package vault

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestLockUnlock1GiBStreaming runs only behind the bigtest build tag, outside
// CI, per PRD section 13. It checks FR-15: locking a 1 GiB file round trips
// and keeps peak memory under 200 MiB.
func TestLockUnlock1GiBStreaming(t *testing.T) {
	const size = 1 << 30 // 1 GiB

	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")

	pattern := bytes.Repeat([]byte("0123456789abcdef"), 1<<20/16) // exactly 1 MiB
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for written := 0; written < size; written += len(pattern) {
		if _, err := f.Write(pattern); err != nil {
			t.Fatalf("writing 1 GiB: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock 1 GiB: %v", err)
	}
	out := filepath.Join(dir, "big.out")
	if _, err := v.Unlock(dst, id, UnlockOptions{Out: out}); err != nil {
		t.Fatalf("Unlock 1 GiB: %v", err)
	}

	h := func(path string) []byte {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("Open %s: %v", path, err)
		}
		defer f.Close()
		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			t.Fatalf("hashing %s: %v", path, err)
		}
		return sum.Sum(nil)
	}
	if !bytes.Equal(h(src), h(out)) {
		t.Fatal("1 GiB round trip mismatch")
	}

	// FR-15: peak RSS under 200 MiB, read from /proc on Linux.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Log("cannot read /proc/self/status, skipping memory check")
		return
	}
	for line := range strings.Lines(string(status)) {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmHWM:" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("parsing VmHWM: %v", err)
			}
			peak := kb * 1024
			t.Logf("peak RSS %d MiB", peak>>20)
			if peak >= 200<<20 {
				t.Fatalf("peak RSS %d MiB exceeds 200 MiB (FR-15)", peak>>20)
			}
			return
		}
	}
	fmt.Println("VmHWM not found")
}
