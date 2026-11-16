//go:build !keenproxy_lite

package trusttunnel

func quicAllowed() bool { return true }
