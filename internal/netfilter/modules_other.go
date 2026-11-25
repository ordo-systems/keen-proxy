//go:build !linux

package netfilter

import "os"

func firmwareCanLoad() bool                               { return false }
func openFirmwareModule(string, string) (*os.File, error) { return nil, ErrModuleNotLoadable }
func loadFirmwareModule(*os.File) error                   { return ErrModuleNotLoadable }
