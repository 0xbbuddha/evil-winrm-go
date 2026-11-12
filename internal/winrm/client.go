// Package winrm wraps github.com/masterzen/winrm with the auth modes and
// convenience helpers evil-winrm-go needs: NTLM password auth (sealed),
// pass-the-hash with sealed NTLM, a PowerShell runner that preserves the working
// directory, and base64 file transfer.
package winrm

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// Config describes how to reach and authenticate against a WinRM endpoint.
// Exactly one authentication mode must be selected: NTLM password, NT hash,
// Kerberos, or a client certificate.
type Config struct {
	Host     string
	Port     int
	HTTPS    bool
	Insecure bool // skip TLS verification
	Username string
	Password string
	Hash     string // hex NT hash for pass-the-hash
	Domain   string
	CACert   []byte
	Timeout  time.Duration

	// Kerberos. Set Kerberos, or just CCache, to select this mode.
	Kerberos  bool
	Realm     string
	SPN       string // default HTTP/<host>
	CCache    string // credential cache; takes priority over Password
	KrbConfig string // krb5.conf path, default /etc/krb5.conf

	// Certificate mutual auth. Both files are PEM. Requires HTTPS.
	CertFile string
	KeyFile  string
}

type authKind int

const (
	authNTLM authKind = iota
	authHash
	authKerberos
	authCert
)

// Client is a connected WinRM session.
type Client struct {
	cfg     Config
	wc      *winrm.Client
	user    string // username as sent to the server (domain-qualified when needed)
	path    string // current remote working directory
	mode    authKind
	scripts []string // remote paths loaded into the persistent session
	sess    *psSession
	conns   *connSet
}

// New builds a Client from cfg, selecting the transport that matches the
// credentials. It does not open a connection; the first command does.
func New(cfg Config) (*Client, error) {
	mode, err := cfg.authMode()
	if err != nil {
		return nil, err
	}

	user := cfg.Username
	if cfg.Domain != "" && mode == authNTLM {
		user = cfg.Domain + "\\" + cfg.Username
	}

	certPEM, keyPEM, err := readKeyPair(cfg)
	if err != nil {
		return nil, err
	}
	endpoint := winrm.NewEndpoint(cfg.Host, cfg.Port, cfg.HTTPS, cfg.Insecure, cfg.CACert, certPEM, keyPEM, cfg.Timeout)
	conns := &connSet{}

	// PT0.2S is how long an empty Receive may hold the only NTLM connection.
	// The next command's stdin cannot be sent until that Receive returns, so
	// this is the worst delay before a command starts, not a command timeout.
	params := winrm.NewParameters("PT0.2S", "en-US", 153600)
	secret := cfg.Password
	switch mode {
	case authHash:
		secret = cfg.Hash
		url := endpointURL(cfg.Host, cfg.Port, cfg.HTTPS)
		params.TransportDecorator = func() winrm.Transporter {
			return &pthTransporter{url: url, user: user, hash: cfg.Hash, cfg: cfg, conns: conns}
		}
	case authCert:
		params.TransportDecorator = func() winrm.Transporter {
			return winrm.NewClientAuthRequestWithDial(conns.Dial)
		}
	case authKerberos:
		settings, err := kerberosSettings(cfg)
		if err != nil {
			return nil, err
		}
		params.TransportDecorator = func() winrm.Transporter {
			return winrm.NewClientKerberos(settings)
		}
	default:
		params.TransportDecorator = func() winrm.Transporter {
			return winrm.NewClientNTLMWithDial(conns.Dial)
		}
	}

	wc, err := winrm.NewClientWithParameters(endpoint, user, secret, params)
	if err != nil {
		return nil, fmt.Errorf("build winrm client: %w", err)
	}
	return &Client{cfg: cfg, wc: wc, user: user, mode: mode, conns: conns}, nil
}

// Identity is the label printed once authentication succeeds.
func (c *Client) Identity() string {
	switch c.mode {
	case authCert:
		return c.cfg.CertFile
	case authKerberos:
		if c.cfg.CCache != "" {
			return c.cfg.Username + " (ccache " + c.cfg.CCache + ")"
		}
		return c.cfg.Username + "@" + c.cfg.Realm
	default:
		if c.user != "" {
			return c.user
		}
		return c.cfg.Username
	}
}

// authMode checks that the credential flags select exactly one transport.
func (cfg Config) authMode() (authKind, error) {
	kerb := cfg.Kerberos || cfg.CCache != ""
	cert := cfg.CertFile != "" || cfg.KeyFile != ""

	switch {
	case cfg.Hash != "" && (kerb || cert || cfg.Password != ""):
		return 0, fmt.Errorf("pass-the-hash cannot be combined with a password, Kerberos or a certificate")
	case cert && kerb:
		return 0, fmt.Errorf("choose either Kerberos or certificate authentication")
	case cert:
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return 0, fmt.Errorf("certificate auth needs both -cert and -key")
		}
		if !cfg.HTTPS {
			return 0, fmt.Errorf("certificate auth requires SSL (-S)")
		}
		return authCert, nil
	case kerb:
		if cfg.CCache == "" && cfg.Password == "" {
			return 0, fmt.Errorf("Kerberos needs a password (-p) or a credential cache (-ccache)")
		}
		if cfg.CCache == "" && (cfg.Realm == "" || cfg.Username == "") {
			return 0, fmt.Errorf("Kerberos password auth needs -u and -realm")
		}
		return authKerberos, nil
	case cfg.Hash != "":
		if cfg.Username == "" {
			return 0, fmt.Errorf("pass-the-hash needs -u")
		}
		return authHash, nil
	case cfg.Password == "" || cfg.Username == "":
		return 0, fmt.Errorf("provide -u and -p, or -H, or Kerberos, or a client certificate")
	default:
		return authNTLM, nil
	}
}

func readKeyPair(cfg Config) (cert, key []byte, err error) {
	if cfg.CertFile == "" && cfg.KeyFile == "" {
		return nil, nil, nil
	}
	cert, err = os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate: %w", err)
	}
	key, err = os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	return cert, key, nil
}

func kerberosSettings(cfg Config) (*winrm.Settings, error) {
	conf := cfg.KrbConfig
	if conf == "" {
		conf = "/etc/krb5.conf"
	}
	if _, err := os.Stat(conf); err != nil {
		return nil, fmt.Errorf("kerberos config %q: %w", conf, err)
	}
	spn := cfg.SPN
	if spn == "" {
		spn = "HTTP/" + cfg.Host
	}
	proto := "http"
	if cfg.HTTPS {
		proto = "https"
	}
	return &winrm.Settings{
		WinRMUsername:          cfg.Username,
		WinRMPassword:          cfg.Password,
		WinRMHost:              cfg.Host,
		WinRMPort:              cfg.Port,
		WinRMProto:             proto,
		WinRMInsecure:          cfg.Insecure,
		WinRMMessageEncryption: true,
		KrbRealm:               cfg.Realm,
		KrbConfig:              conf,
		KrbSpn:                 spn,
		KrbCCache:              cfg.CCache,
	}, nil
}

// Ping verifies connectivity and credentials by running a trivial command.
func (c *Client) Ping(ctx context.Context) error {
	_, _, _, err := c.run(ctx, "$true | Out-Null")
	return err
}

// run executes a raw PowerShell snippet and returns stdout, stderr and the exit
// code. It is the low-level primitive behind RunPS and the file helpers.
func (c *Client) run(ctx context.Context, ps string) (stdout, stderr string, code int, err error) {
	var out, errb bytes.Buffer
	code, err = c.wc.RunWithContext(ctx, winrm.Powershell(ps), &out, &errb)
	return out.String(), errb.String(), code, err
}

// endpointURL mirrors masterzen's unexported Endpoint.url so the custom
// pass-the-hash transport posts to exactly the address encoded in the SOAP
// envelopes.
func endpointURL(host string, port int, https bool) string {
	scheme := "http"
	if https {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/wsman"
}

// pthTransporter implements winrm.Transporter, posting SOAP over the
// pass-the-hash NTLM round tripper. It stores its own url/credentials because
// winrm.Client's fields are unexported and unreachable from here.
type pthTransporter struct {
	url    string
	user   string
	hash   string
	cfg    Config
	conns  *connSet
	client *http.Client
}

// Transport builds the HTTP client used for every Post. NTLM sealing is
// applied by the round tripper; TLS is only used when -S is set.
func (t *pthTransporter) Transport(ep *winrm.Endpoint) error {
	tlsCfg := &tls.Config{InsecureSkipVerify: ep.Insecure, ServerName: ep.TLSServerName} //nolint:gosec // -S trust is the operator's call
	base := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext:     t.conns.DialContext,
		// NTLM is connection-oriented: pin to a single reusable connection.
		MaxConnsPerHost:       1,
		MaxIdleConnsPerHost:   1,
		DisableKeepAlives:     false,
		IdleConnTimeout:       0,
		ResponseHeaderTimeout: ep.Timeout,
	}
	t.client = &http.Client{Transport: &pthRoundTripper{base: base}}
	return nil
}

// Post sends one SOAP message and returns the body, matching the contract
// masterzen expects from a Transporter.
func (t *pthTransporter) Post(_ *winrm.Client, message *soap.SoapMessage) (string, error) {
	req, err := http.NewRequest(http.MethodPost, t.url, strings.NewReader(message.String()))
	if err != nil {
		return "", fmt.Errorf("pth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(t.user, t.hash)

	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pth: post: %w", err)
	}
	defer resp.Body.Close()

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return "", fmt.Errorf("pth: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: %s", resp.StatusCode, body.String())
	}
	return body.String(), nil
}

// connSet remembers the sockets a session opened. Close drops them so an
// idle WinRM Receive cannot keep exit waiting on the operation timeout.
type connSet struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (s *connSet) Dial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	s.add(c)
	return c, nil
}

func (s *connSet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	s.add(c)
	return c, nil
}

func (s *connSet) add(c net.Conn) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

// drop closes every tracked socket. It reports whether any were open.
func (s *connSet) drop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) == 0 {
		return false
	}
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	return true
}
