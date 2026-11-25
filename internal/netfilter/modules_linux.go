package netfilter

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// firmwareCanLoad tests the effective capability; a UID of zero is not enough
// in a container or after the kernel permanently disables module loading.
func firmwareCanLoad() bool {
	data, err := os.ReadFile("/proc/sys/kernel/modules_disabled")
	if err != nil || string(data) != "0\n" {
		return false
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	return unix.Capget(&header, &caps[0]) == nil && caps[0].Effective&(1<<unix.CAP_SYS_MODULE) != 0
}

// Open by descriptor and pass that descriptor to the kernel. Neither paths nor
// module parameters are taken from HTTP, and files cannot escape via symlinks.
func openFirmwareModule(release, name string) (*os.File, error) {
	if !keeneticRelease.MatchString(release) || (name != FirmwareModuleName("guard") && name != FirmwareModuleName("tproxy")) {
		return nil, ErrModuleNotLoadable
	}
	lib, err := openFirmwareDir(unix.AT_FDCWD, "/lib")
	if err != nil {
		return nil, err
	}
	defer unix.Close(lib)
	base, err := openFirmwareDir(lib, "modules")
	if err != nil {
		return nil, err
	}
	defer unix.Close(base)
	return openModuleAt(base, release, name)
}

func openModuleAt(base int, release, name string) (*os.File, error) {
	dir, err := openFirmwareDir(base, release)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name+".ko", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := checkFirmwareOwner(fd, unix.S_IFREG); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name+".ko"), nil
}

func openFirmwareDir(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := checkFirmwareOwner(fd, unix.S_IFDIR); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func checkFirmwareOwner(fd int, kind uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	mode := uint32(st.Mode)
	if st.Uid != 0 || mode&0o022 != 0 || mode&unix.S_IFMT != kind {
		return fmt.Errorf("unsafe firmware module location")
	}
	return nil
}

func loadFirmwareModule(file *os.File) error {
	err := unix.FinitModule(int(file.Fd()), "", 0)
	if err == unix.EEXIST {
		return nil // A concurrent system loader won; the caller rechecks registration.
	}
	return err
}
