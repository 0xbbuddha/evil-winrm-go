package winrm

import "strings"
import "testing"

func TestAuthMode(t *testing.T) {
	base := Config{Host: "dc.lab.local", Username: "alice", Password: "pw"}

	mode, err := base.authMode()
	if err != nil || mode != authNTLM {
		t.Fatalf("password: mode=%v err=%v", mode, err)
	}

	hash := base
	hash.Password = ""
	hash.Hash = "aa"
	hash.HTTPS = true
	if mode, err = hash.authMode(); err != nil || mode != authHash {
		t.Fatalf("hash: mode=%v err=%v", mode, err)
	}

	kerb := base
	kerb.Kerberos = true
	kerb.Realm = "LAB.LOCAL"
	if mode, err = kerb.authMode(); err != nil || mode != authKerberos {
		t.Fatalf("kerberos: mode=%v err=%v", mode, err)
	}

	ccache := Config{Host: "dc.lab.local", CCache: "/tmp/krb5cc"}
	if mode, err = ccache.authMode(); err != nil || mode != authKerberos {
		t.Fatalf("ccache: mode=%v err=%v", mode, err)
	}

	cert := Config{Host: "dc", HTTPS: true, CertFile: "c.pem", KeyFile: "k.pem"}
	if mode, err = cert.authMode(); err != nil || mode != authCert {
		t.Fatalf("cert: mode=%v err=%v", mode, err)
	}

	bad := []Config{
		{Host: "h", Username: "u", Password: "p", Hash: "aa"},
		{Host: "h", Hash: "aa"},
		{Host: "h", HTTPS: true, CertFile: "c.pem"},
		{Host: "h", CertFile: "c.pem", KeyFile: "k.pem"},
		{Host: "h", Kerberos: true, Username: "u", Password: "p"},
		{Host: "h", Kerberos: true, CCache: "/tmp/cc", CertFile: "c.pem", KeyFile: "k.pem", HTTPS: true},
		{},
	}
	for i, cfg := range bad {
		if _, err := cfg.authMode(); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestKerberosSettingsRequireConfig(t *testing.T) {
	_, err := kerberosSettings(Config{Host: "dc", KrbConfig: "/no/such/krb5.conf"})
	if err == nil || !strings.Contains(err.Error(), "krb5.conf") {
		t.Fatalf("err = %v", err)
	}
}
