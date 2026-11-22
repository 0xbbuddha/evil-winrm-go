// PSRP (MS-PSRP) support, layered on go-psrpcore for the protocol engine and
// our own WSMan SOAP + NTLM-sealing transport. Opening a RunspacePool sends the
// PSRP handshake fragments as the creationXml of a sealed WSMan Create; running
// a script sends a CREATE_PIPELINE via WSMan Command and reads typed PSRP
// output back through WSMan Receive.
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
	msgID   uint64
}

// OpenPSRP opens a RunspacePool: it sends the PSRP handshake fragments as the
// creationXml of a sealed WSMan Create, then reads the pool-opened messages.
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

func msgUUID() string { return "uuid:" + strings.ToUpper(uuid.New().String()) }
