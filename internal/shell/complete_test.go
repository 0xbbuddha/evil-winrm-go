package shell

import "testing"

func TestSplitToken(t *testing.T) {
	token, cmd, n := splitToken("cd ")
	if token != "" || cmd != "cd" || n != 1 {
		t.Fatalf("cd space: %q %q %d", token, cmd, n)
	}
	token, cmd, n = splitToken("up")
	if token != "up" || n != 0 {
		t.Fatalf("command: %q %d", token, n)
	}
	token, cmd, n = splitToken(`upload /tmp/a`)
	if cmd != "upload" || n != 1 || token != "/tmp/a" {
		t.Fatalf("upload: %q %q %d", token, cmd, n)
	}
}

func TestSuffixes(t *testing.T) {
	got := suffixes(`C:\Us`, []string{`C:\Users\`})
	if len(got) != 1 || string(got[0]) != `ers\` {
		t.Fatalf("got %#v", got)
	}
}
