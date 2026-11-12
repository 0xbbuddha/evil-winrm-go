package winrm

import (
	"errors"
	"net"
	"strings"
)

// Explain turns a WinRM or network error into one short line. Library errors
// repeat the NTLM handshake failure and the HTTP URL; the useful part is the
// address and the reason the connection stopped.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		if op.Addr != nil {
			return op.Addr.String() + ": " + op.Err.Error()
		}
		return op.Err.Error()
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "lookup " + dns.Name + ": " + dns.Err
	}
	s := err.Error()
	s = strings.ReplaceAll(s, "ntlm: negotiate message encryption: ", "")
	s = strings.ReplaceAll(s, "unknown error ", "")
	return strings.TrimSpace(s)
}
