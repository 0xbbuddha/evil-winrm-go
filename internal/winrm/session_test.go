package winrm

import (
	"strings"
	"testing"
)

func TestSplitFrame(t *testing.T) {
	marker := "@@EWRM_abc@@"
	buf := []byte("hello\n" + marker + "C:\\Users\\a\\Documents\r\n")
	out, path, ok := splitFrame(buf, marker)
	if !ok {
		t.Fatal("expected a complete frame")
	}
	if out != "hello\n" || path != `C:\Users\a\Documents` {
		t.Fatalf("out=%q path=%q", out, path)
	}
	if _, _, ok := splitFrame([]byte("hello\n"+marker+"C:\\x"), marker); ok {
		t.Fatal("path without newline must wait")
	}
}

func TestParseTargets(t *testing.T) {
	in := "# lab\n\n127.0.0.1\n10.0.0.5:5995\n[::1]:5986\n"
	got, err := ParseTargets(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Host != "127.0.0.1" || got[0].Port != 0 {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].Host != "10.0.0.5" || got[1].Port != 5995 {
		t.Fatalf("second: %+v", got[1])
	}
	if got[2].Host != "::1" || got[2].Port != 5986 {
		t.Fatalf("third: %+v", got[2])
	}
}
