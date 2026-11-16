//go:build !with_quic

package engine

// quicIncluded is false in keenproxy_lite. HTTP/3 must fail closed, not downgrade.
const quicIncluded = false
