// PSRP (MS-PSRP) support, layered on go-psrpcore for the protocol engine and
// our own WSMan SOAP + NTLM-sealing transport. Opening a RunspacePool sends the
// PSRP handshake fragments as the creationXml of a sealed WSMan Create; running
// a script sends a CREATE_PIPELINE via WSMan Command and reads typed PSRP
// output back through WSMan Receive.
package winrm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	krbcred "github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/smnsjas/go-psrpcore/messages"
	psrppipe "github.com/smnsjas/go-psrpcore/pipeline"
	psrprs "github.com/smnsjas/go-psrpcore/runspace"
	"github.com/smnsjas/go-psrpcore/serialization"
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

const (
	wsmanResourcePowerShell = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
	wsmanNsShell            = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	wsmanActionCreate       = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	wsmanActionCommand      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	wsmanActionReceive      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	wsmanActionSend         = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
	// protocolVersion 2.3 = PowerShell 5.x; the server negotiates down.
	psrpProtocolVersion = "2.3"
	fragmentHeaderSize  = 21 // ObjectId(8) + FragmentId(8) + Flags(1) + BlobLength(4)
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

// psrpTransport builds the HTTP client and the per-request auth applier for the
// configured mode. NTLM and pass-the-hash seal a pinned connection; certificate
// auth uses a TLS client certificate over HTTPS and carries no HTTP credentials.
func psrpTransport(cfg Config, conns *connSet) (*http.Client, func(*http.Request) error, string, error) {
	mode, err := cfg.authMode()
	if err != nil {
		return nil, nil, "", err
	}
	switch mode {
	case authCert:
		client, cerr := certHTTPClient(cfg, conns)
		if cerr != nil {
			return nil, nil, "", cerr
		}
		// WinRM certificate auth is signalled by this fixed Authorization value;
		// the actual authentication is the TLS client certificate.
		return client, func(r *http.Request) error {
			r.Header.Set("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")
			return nil
		}, cfg.Username, nil
	case authKerberos:
		// shortcut: Kerberos rides SPNEGO over HTTPS (TLS carries encryption);
		// plain-HTTP GSS message sealing is not implemented, so HTTPS is required.
		if !cfg.HTTPS {
			return nil, nil, "", fmt.Errorf("kerberos on PSRP requires HTTPS (-S); plain-HTTP sealing is not implemented")
		}
		cl, spn, kerr := kerbClient(cfg)
		if kerr != nil {
			return nil, nil, "", kerr
		}
		apply := func(r *http.Request) error { return spnego.SetSPNEGOHeader(cl, r, spn) }
		return plainTLSClient(cfg, conns), apply, cfg.Username, nil
	default: // authNTLM, authHash
		user, secret, aerr := psrpAuth(cfg)
		if aerr != nil {
			return nil, nil, "", aerr
		}
		return sealedHTTPClient(cfg, conns), func(r *http.Request) error { r.SetBasicAuth(user, secret); return nil }, user, nil
	}
}

// plainTLSClient is an HTTPS client with no HTTP-layer auth (used by Kerberos,
// which authenticates with a per-request SPNEGO header).
func plainTLSClient(cfg Config, conns *connSet) *http.Client {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.Insecure} //nolint:gosec // operator's -k
	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cfg.CACert)
		tlsCfg.RootCAs = pool
	}
	base := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         conns.DialContext,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	return &http.Client{Transport: base}
}

// kerbClient loads a Kerberos client from the credential cache and resolves the
// service principal (defaulting to HTTP/<host>).
func kerbClient(cfg Config) (*krbclient.Client, string, error) {
	confPath := cfg.KrbConfig
	if confPath == "" {
		confPath = "/etc/krb5.conf"
	}
	conf, err := krbconfig.Load(confPath)
	if err != nil {
		return nil, "", fmt.Errorf("krb5.conf: %w", err)
	}
	ccPath := strings.TrimPrefix(cfg.CCache, "FILE:")
	if ccPath == "" {
		ccPath = strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
	}
	if ccPath == "" {
		return nil, "", fmt.Errorf("kerberos needs a credential cache (-ccache or KRB5CCNAME)")
	}
	cc, err := krbcred.LoadCCache(ccPath)
	if err != nil {
		return nil, "", fmt.Errorf("load ccache: %w", err)
	}
	cl, err := krbclient.NewFromCCache(cc, conf, krbclient.DisablePAFXFAST(true))
	if err != nil {
		return nil, "", fmt.Errorf("kerberos client: %w", err)
	}
	spn := cfg.SPN
	if spn == "" {
		spn = "HTTP/" + cfg.Host
	}
	return cl, spn, nil
}

// certHTTPClient builds an HTTPS client that authenticates with a TLS client
// certificate (WinRM certificate mapping); TLS provides the encryption.
func certHTTPClient(cfg Config, conns *connSet) (*http.Client, error) {
	certPEM, keyPEM, err := readKeyPair(cfg)
	if err != nil {
		return nil, err
	}
	if certPEM == nil {
		return nil, fmt.Errorf("certificate auth needs -cert and -key")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	tlsCfg := &tls.Config{ //nolint:gosec // operator's -k
		Certificates:       []tls.Certificate{pair},
		InsecureSkipVerify: cfg.Insecure,
		// WinRM may ask for the client cert via TLS renegotiation after the
		// handshake, which Go's client refuses unless allowed.
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cfg.CACert)
		tlsCfg.RootCAs = pool
	}
	base := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         conns.DialContext,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	return &http.Client{Transport: base}, nil
}

// PSRPSession is a PSRP runspace opened over WSMan.
type PSRPSession struct {
	cfg       Config
	url       string
	user      string
	conns     *connSet
	client    *http.Client
	authApply func(*http.Request) error // sets per-request auth (Basic for NTLM/PtH; SPNEGO for Kerberos; none for cert)
	pool      *psrprs.Pool
	shellID   string
	msgID     uint64
}

// OpenPSRP opens a RunspacePool: it sends the PSRP handshake fragments as the
// creationXml of a sealed WSMan Create, then reads the pool-opened messages.
func OpenPSRP(ctx context.Context, cfg Config) (*PSRPSession, error) {
	conns := &connSet{}
	client, authApply, user, err := psrpTransport(cfg, conns)
	if err != nil {
		return nil, err
	}
	s := &PSRPSession{
		cfg:       cfg,
		url:       endpointURL(cfg.Host, cfg.Port, cfg.HTTPS),
		user:      user,
		conns:     conns,
		client:    client,
		authApply: authApply,
	}

	transport := &wsmanRW{sess: s, commandID: ""}
	s.pool = psrprs.New(transport, uuid.New())
	s.pool.SkipHandshakeSend = true // handshake rides in the Create creationXml

	frags, err := s.pool.GetHandshakeFragments()
	if err != nil {
		return nil, fmt.Errorf("psrp handshake fragments: %w", err)
	}
	shellID, err := s.create(ctx, base64.StdEncoding.EncodeToString(frags))
	if err != nil {
		return nil, err
	}
	s.shellID = shellID
	transport.ctx = ctx

	if err := s.pool.Open(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("open runspace pool: %w", err)
	}
	return s, nil
}

// ShellID returns the opened runspace's shell id.
func (s *PSRPSession) ShellID() string { return s.shellID }

// Close drops the pinned connection(s).
func (s *PSRPSession) Close() { s.conns.drop() }

// Execute runs script in the runspace and returns its combined textual output.
func (s *PSRPSession) Execute(ctx context.Context, script string) (string, error) {
	pl, err := s.pool.CreatePipeline(script)
	if err != nil {
		return "", fmt.Errorf("create pipeline: %w", err)
	}
	s.msgID++
	createData, err := pl.GetCreatePipelineDataWithID(s.msgID)
	if err != nil {
		return "", fmt.Errorf("create pipeline data: %w", err)
	}
	cmdID, err := s.command(ctx, base64.StdEncoding.EncodeToString(createData))
	if err != nil {
		return "", err
	}
	pl.SkipInvokeSend() // the CREATE_PIPELINE already went out as Command arguments
	if err := pl.Invoke(ctx); err != nil {
		return "", fmt.Errorf("invoke pipeline: %w", err)
	}

	// Collect typed output while we pump Receive responses into the pipeline.
	var out strings.Builder
	deser := serialization.NewDeserializer()
	defer deser.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for msg := range pl.Output() {
			out.WriteString(renderOutput(deser, msg))
		}
	}()

	if err := s.pumpPipeline(ctx, cmdID, pl); err != nil {
		return out.String(), err
	}
	<-done
	return out.String(), nil
}

// pumpPipeline reads WSMan Receive responses for cmdID, reassembles PSRP
// fragments into messages and feeds them to the pipeline until it completes.
func (s *PSRPSession) pumpPipeline(ctx context.Context, cmdID string, pl *psrppipe.Pipeline) error {
	var frag fragmentReader
	for {
		select {
		case <-pl.Done():
			return nil
		default:
		}
		stdout, done, err := s.receive(ctx, cmdID)
		if err != nil {
			pl.Fail(err)
			return err
		}
		for _, msg := range frag.feed(stdout) {
			if err := pl.HandleMessage(msg); err != nil {
				pl.Fail(err)
				return fmt.Errorf("handle message: %w", err)
			}
		}
		if done {
			return nil
		}
	}
}

// renderOutput turns a PSRP output/error message into text.
func renderOutput(d *serialization.Deserializer, msg *messages.Message) string {
	switch msg.Type {
	case messages.MessageTypePipelineOutput, messages.MessageTypeErrorRecord:
		vals, err := d.Deserialize(msg.Data)
		if err != nil {
			return ""
		}
		var b strings.Builder
		for _, v := range vals {
			fmt.Fprintln(&b, stringifyPS(v))
		}
		return b.String()
	default:
		return ""
	}
}

func stringifyPS(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case *serialization.PSObject:
		if t.ToString != "" {
			return t.ToString
		}
		return t.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// wsmanRW bridges go-psrpcore's io.ReadWriter transport to WSMan Send/Receive
// for the runspace-pool stream (empty command id).
type wsmanRW struct {
	sess      *PSRPSession
	commandID string
	ctx       context.Context
	buf       []byte
}

func (t *wsmanRW) Read(p []byte) (int, error) {
	for len(t.buf) == 0 {
		stdout, _, err := t.sess.receive(t.ctx, t.commandID)
		if err != nil {
			return 0, err
		}
		t.buf = append(t.buf, stdout...)
	}
	n := copy(p, t.buf)
	t.buf = t.buf[n:]
	return n, nil
}

func (t *wsmanRW) Write(p []byte) (int, error) {
	if err := t.sess.send(t.ctx, t.commandID, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// fragmentReader reassembles a PSRP fragment byte stream (across Receive calls)
// into complete messages.
type fragmentReader struct {
	stream []byte
	msg    []byte
}

func (f *fragmentReader) feed(b []byte) []*messages.Message {
	f.stream = append(f.stream, b...)
	var out []*messages.Message
	for len(f.stream) >= fragmentHeaderSize {
		blobLen := int(f.stream[17])<<24 | int(f.stream[18])<<16 | int(f.stream[19])<<8 | int(f.stream[20])
		total := fragmentHeaderSize + blobLen
		if len(f.stream) < total {
			break // wait for the rest of this fragment
		}
		flags := f.stream[16]
		blob := f.stream[fragmentHeaderSize:total]
		if flags&0x1 != 0 { // start
			f.msg = f.msg[:0]
		}
		f.msg = append(f.msg, blob...)
		if flags&0x2 != 0 { // end
			if m, err := messages.Decode(f.msg); err == nil {
				out = append(out, m)
			}
			f.msg = f.msg[:0]
		}
		f.stream = f.stream[total:]
	}
	return out
}

// create sends the WSMan Create and returns the server's ShellId.
func (s *PSRPSession) create(ctx context.Context, creationXML string) (string, error) {
	body := fmt.Sprintf(`<rsp:Shell ShellId="%s" xmlns:rsp="%s"><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams><rsp:IdleTimeOut>PT30M</rsp:IdleTimeOut><creationXml xmlns="http://schemas.microsoft.com/powershell">%s</creationXml></rsp:Shell>`,
		strings.ToUpper(uuid.New().String()), wsmanNsShell, creationXML)
	env := soapEnvelope(wsmanActionCreate, s.url, wsmanResourcePowerShell, msgUUID(), "", protocolOptionSet(psrpProtocolVersion), body)
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
	if s.authApply != nil {
		if err := s.authApply(req); err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
	}
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

func msgUUID() string { return "uuid:" + strings.ToUpper(uuid.New().String()) }
