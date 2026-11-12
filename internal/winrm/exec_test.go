package winrm

import "testing"

func TestPSQuote(t *testing.T) {
	cases := map[string]string{
		`C:\Temp`:   `'C:\Temp'`,
		`it's here`: `'it''s here'`,
		``:          `''`,
		`a'b'c`:     `'a''b''c'`,
	}
	for in, want := range cases {
		if got := psQuote(in); got != want {
			t.Errorf("psQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripSpace(t *testing.T) {
	in := "ab cd\tef\r\ngh"
	if got := stripSpace(in); got != "abcdefgh" {
		t.Errorf("stripSpace = %q", got)
	}
}

func TestAbsRemote(t *testing.T) {
	c := &Client{path: `C:\Users\admin`}
	cases := map[string]string{
		"loot.txt":         `C:\Users\admin\loot.txt`,
		`C:\Windows\x.exe`: `C:\Windows\x.exe`,
		`\\srv\share\f`:    `\\srv\share\f`,
		"":                 `C:\Users\admin`,
	}
	for in, want := range cases {
		if got := c.absRemote(in); got != want {
			t.Errorf("absRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
