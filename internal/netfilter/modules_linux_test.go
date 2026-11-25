package netfilter

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFirmwareModuleRejectsUnlistedInputs(t *testing.T) {
	for _, pair := range [][2]string{{"../4.9-ndm-5", "xt_comment"}, {"4.9-ndm-5", "../xt_comment"}, {"4.9-ndm-5", "xt_socket"}} {
		if file, err := openFirmwareModule(pair[0], pair[1]); !errors.Is(err, ErrModuleNotLoadable) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("unexpected result for %v: %v", pair, err)
		}
	}
}

func TestFirmwareModuleOpensOnlyTrustedRegularFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixture must be owned by root")
	}
	base := t.TempDir()
	const release, name = "4.9-ndm-5", "xt_comment"
	dir := filepath.Join(base, release)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".ko")
	const contents = "inert module fixture"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := openFirmwareDir(unix.AT_FDCWD, base)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	file, err := openModuleAt(fd, release, name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(got) != contents {
		t.Fatalf("opened wrong file: %q, %v", got, err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if file, err := openModuleAt(fd, release, name); err == nil {
		file.Close()
		t.Fatal("opened group-writable module")
	}
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+".real", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if file, err := openModuleAt(fd, release, name); !errors.Is(err, unix.ELOOP) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("expected rejection of symlinked module, got %v", err)
	}
}
