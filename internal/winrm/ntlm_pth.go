package winrm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// pthRoundTripper authenticates with an NT hash and seals every SOAP body
// (MS-NLMP + MS-WSMV). Sealing is what lets pass-the-hash work on plain HTTP,
// where WinRM refuses an unencrypted message.
type pthRoundTripper struct {
	base http.RoundTripper

	mu     sync.Mutex
	seal   *sealedNTLM
	scheme string
}

// RoundTrip handshakes once per connection, then sends the request body sealed.
func (t *pthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	username, hash, ok := req.BasicAuth()
	if !ok {
		return t.base.RoundTrip(req)
	}
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seal == nil {
		return t.handshake(req, username, hash, body)
	}
	resp, err := t.sendSealed(req, body, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		drain(resp)
		t.seal = nil
		return t.handshake(req, username, hash, body)
	}
	return resp, nil
}

func (t *pthRoundTripper) handshake(req *http.Request, username, hash string, body []byte) (*http.Response, error) {
	// The first request on the connection must be the NEGOTIATE token. An
	// unauthenticated probe would consume the server's challenge and the
	// following negotiate comes back as HTTP 500.
	scheme := "Negotiate"
	token, key, flags, err := negotiateAzureNTLMSessionKey(username, hash, func(negotiate []byte) ([]byte, error) {
		resp, err := t.postAuth(req, scheme, negotiate, nil)
		if err != nil {
			return nil, err
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, fmt.Errorf("pth: negotiate expected 401, got %d", resp.StatusCode)
		}
		return schemeToken(resp.Header, scheme)
	})
	if err != nil {
		return nil, err
	}
	session, err := newAzureNTLMSecuritySession(key, flags, true, NTLMKeyExchangeOptions{})
	if err != nil {
		return nil, err
	}
	t.seal = newSealedNTLM(session)
	t.scheme = scheme
	// The AUTHENTICATE token and the first sealed SOAP body travel together.
	// An empty follow-up request is rejected with HTTP 500 by this WinRM.
	return t.sendSealed(req, body, scheme+" "+base64.StdEncoding.EncodeToString(token))
}

func (t *pthRoundTripper) postAuth(req *http.Request, scheme string, token, body []byte) (*http.Response, error) {
	r := t.cloneWithBody(req, body)
	if len(body) == 0 {
		r.Header.Del("Content-Type")
	}
	r.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(token))
	return t.base.RoundTrip(r)
}

func (t *pthRoundTripper) sendSealed(req *http.Request, body []byte, authorization string) (*http.Response, error) {
	sealed, err := t.seal.seal(body)
	if err != nil {
		return nil, fmt.Errorf("pth: seal: %w", err)
	}
	r := t.cloneWithBody(req, sealed)
	r.Header.Del("Authorization")
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	r.Header.Set("Content-Type", t.seal.contentType())
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp.StatusCode == http.StatusUnauthorized {
		return resp, err
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	plain := raw
	if strings.Contains(resp.Header.Get("Content-Type"), "multipart/") {
		plain, err = t.seal.open(raw)
		if err != nil {
			return nil, fmt.Errorf("pth: unseal: %w", err)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(plain))
	resp.ContentLength = int64(len(plain))
	resp.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	return resp, nil
}

// cloneWithBody returns a shallow copy of req with a rewound in-memory body so
// the same request can be replayed across handshake steps.
func (t *pthRoundTripper) cloneWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	return clone
}

// schemeToken extracts the base64 challenge token for scheme from the 401
// response headers.
func schemeToken(h http.Header, scheme string) ([]byte, error) {
	for _, v := range h.Values("WWW-Authenticate") {
		field := strings.Fields(v)
		if len(field) == 2 && strings.EqualFold(field[0], scheme) {
			return base64.StdEncoding.DecodeString(field[1])
		}
	}
	return nil, fmt.Errorf("no %s challenge in response", scheme)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
