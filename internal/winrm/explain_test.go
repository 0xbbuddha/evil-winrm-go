package winrm

import (
	"errors"
	"net"
	"testing"
)

func TestExplainDial(t *testing.T) {
	err := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5999},
		Err:  errors.New("connect: connection refused"),
	}
	wrapped := errors.New("connection/authentication failed: unknown error Post \"http://127.0.0.1:5999/wsman\": ntlm: negotiate message encryption: " + err.Error())
	// errors.As only walks Unwrap, so wrap it properly.
	got := Explain(&wrapErr{msg: "connection/authentication failed", err: err})
	if got != "127.0.0.1:5999: connect: connection refused" {
		t.Fatalf("got %q (wrapped sample %s)", got, wrapped)
	}
}

type wrapErr struct {
	msg string
	err error
}

func (w *wrapErr) Error() string { return w.msg + ": " + w.err.Error() }
func (w *wrapErr) Unwrap() error { return w.err }
