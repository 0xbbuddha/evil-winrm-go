// PSRP (MS-PSRP) support, layered on go-psrpcore for the protocol engine and
// our own WSMan SOAP + NTLM-sealing transport. This file is the milestone-1
// slice: open a RunspacePool by sending a sealed WSMan Create whose creationXml
// carries the PSRP handshake fragments, and return the shell id.
package winrm

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	psrprs "github.com/smnsjas/go-psrpcore/runspace"
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

const (
	wsmanResourcePowerShell = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
	wsmanNsShell            = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	wsmanActionCreate       = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	// protocolVersion 2.3 = PowerShell 5.x; 2.2 = PS3/4. The server negotiates down.
	psrpProtocolVersion = "2.3"
)

// ntHash returns the NT hash (MD4 of the UTF-16LE password) as lowercase hex,
// so password auth reuses the same sealing path as pass-the-hash.
func ntHash(password string) (string, error) {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	b, err := enc.Bytes([]byte(password))
	if err != nil {
		return "", fmt.Errorf("utf16 password: %w", err)
	}
	h := md4.New()
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// psrpAuth resolves the NTLM secret for sealing: the NT hash verbatim for
// pass-the-hash, otherwise one derived from the password.
func psrpAuth(cfg Config) (user, secret string, err error) {
	user = cfg.Username
	if cfg.Domain != "" {
		user = cfg.Domain + "\\" + cfg.Username
	}
	if cfg.Hash != "" {
		return user, cfg.Hash, nil
	}
	secret, err = ntHash(cfg.Password)
	return user, secret, err
}

// sealedHTTPClient builds the single-connection, NTLM-sealing HTTP client that
// every PSRP WSMan request rides, reusing the pass-the-hash round tripper.
func sealedHTTPClient(cfg Config, conns *connSet) *http.Client {
	base := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec // operator's -k
		DialContext:         conns.DialContext,
		MaxConnsPerHost:     1, // NTLM seals a single pinned connection
		MaxIdleConnsPerHost: 1,
	}
	return &http.Client{Transport: &pthRoundTripper{base: base}}
}

// PSRPSession is a PSRP runspace opened over WSMan.
type PSRPSession struct {
	cfg     Config
	url     string
	user    string
	secret  string
	conns   *connSet
	client  *http.Client
	pool    *psrprs.Pool
	shellID string
}

// OpenPSRP opens a RunspacePool: it extracts the PSRP handshake fragments from
// go-psrpcore and sends them as the creationXml of a sealed WSMan Create.
func OpenPSRP(ctx context.Context, cfg Config) (*PSRPSession, error) {
	user, secret, err := psrpAuth(cfg)
	if err != nil {
		return nil, err
	}
	conns := &connSet{}
	s := &PSRPSession{
		cfg:    cfg,
		url:    endpointURL(cfg.Host, cfg.Port, cfg.HTTPS),
		user:   user,
		secret: secret,
		conns:  conns,
		client: sealedHTTPClient(cfg, conns),
	}

	// The pool needs a transport for later message I/O; milestone 1 only reads
	// the handshake fragments, which touch no transport. nopRW stands in.
	s.pool = psrprs.New(nopRW{}, uuid.New())
	s.pool.SkipHandshakeSend = true

	frags, err := s.pool.GetHandshakeFragments()
	if err != nil {
		return nil, fmt.Errorf("psrp handshake fragments: %w", err)
	}
	creationXML := base64.StdEncoding.EncodeToString(frags)

	shellID, err := s.create(ctx, creationXML)
	if err != nil {
		return nil, err
	}
	s.shellID = shellID
	return s, nil
}

// ShellID returns the opened runspace's shell id.
func (s *PSRPSession) ShellID() string { return s.shellID }

// Close drops the pinned connection(s).
func (s *PSRPSession) Close() { s.conns.drop() }

// create sends the WSMan Create and returns the server's ShellId.
func (s *PSRPSession) create(ctx context.Context, creationXML string) (string, error) {
	msgID := "uuid:" + strings.ToUpper(uuid.New().String())
	shellID := strings.ToUpper(uuid.New().String())
	body := fmt.Sprintf(`<rsp:Shell ShellId="%s" xmlns:rsp="%s"><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams><rsp:IdleTimeOut>PT30M</rsp:IdleTimeOut><creationXml xmlns="http://schemas.microsoft.com/powershell">%s</creationXml></rsp:Shell>`,
		shellID, wsmanNsShell, creationXML)
	env := soapEnvelope(wsmanActionCreate, s.url, wsmanResourcePowerShell, msgID, psrpProtocolVersion, body)

	resp, err := s.post(ctx, env)
	if err != nil {
		return "", err
	}
	var cr struct {
		Selectors []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Body>ResourceCreated>ReferenceParameters>SelectorSet>Selector"`
	}
	if err := xml.Unmarshal(resp, &cr); err != nil {
		return "", fmt.Errorf("parse create response: %w", err)
	}
	for _, sel := range cr.Selectors {
		if sel.Name == "ShellId" {
			return sel.Value, nil
		}
	}
	return "", fmt.Errorf("create response had no ShellId: %s", snippet(resp))
}

// post sends one SOAP body over the sealed transport and returns the response.
func (s *PSRPSession) post(ctx context.Context, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.SetBasicAuth(s.user, s.secret)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("psrp post: %w", err)
	}
	defer resp.Body.Close()
	out, err := readAll(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, snippet(out))
	}
	return out, nil
}

// nopRW is a placeholder io.ReadWriter for the pool before the WSMan message
// transport is wired (milestone 2).
type nopRW struct{}

func (nopRW) Read([]byte) (int, error)  { return 0, fmt.Errorf("psrp transport not wired yet") }
func (nopRW) Write(p []byte) (int, error) { return len(p), nil }
