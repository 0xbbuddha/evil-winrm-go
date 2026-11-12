package winrm

import (
	"bytes"
	"fmt"
	"strconv"
)

// MIME framing for a sealed WinRM body (MS-WSMV 2.2.9.1). The protector is
// the NTLM session built from an NT hash.
const sealBoundary = "--Encrypted Boundary"

type sealedNTLM struct {
	p azureNTLMMessageProtector
}

func newSealedNTLM(session *azureNTLMSecuritySession) *sealedNTLM {
	return &sealedNTLM{p: azureNTLMMessageProtector{session: session}}
}

func (s *sealedNTLM) contentType() string {
	return `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`
}

func (s *sealedNTLM) seal(message []byte) ([]byte, error) {
	wrapped, err := s.p.Wrap(message)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(sealBoundary)
	b.WriteString("\r\n")
	b.WriteString("\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", len(message))
	b.WriteString(sealBoundary)
	b.WriteString("\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	b.Write(wrapped)
	b.WriteString(sealBoundary)
	b.WriteString("--\r\n")
	return b.Bytes(), nil
}

func (s *sealedNTLM) open(body []byte) ([]byte, error) {
	sep := []byte(sealBoundary + "\r\n")
	parts := bytes.Split(body, sep)
	var kept [][]byte
	for _, part := range parts {
		if len(part) > 0 {
			kept = append(kept, part)
		}
	}
	if len(kept) < 2 || len(kept)%2 != 0 {
		return nil, fmt.Errorf("sealed response is not a WinRM encrypted multipart (%d parts)", len(kept))
	}
	var out bytes.Buffer
	for i := 0; i < len(kept); i += 2 {
		header, payload := kept[i], kept[i+1]
		want, err := originalLength(header)
		if err != nil {
			return nil, err
		}
		const octet = "\tContent-Type: application/octet-stream\r\n"
		payload = bytes.TrimSuffix(payload, []byte(sealBoundary+"--\r\n"))
		if !bytes.HasPrefix(payload, []byte(octet)) {
			return nil, fmt.Errorf("sealed response is missing the octet-stream part")
		}
		plain, err := s.p.Unwrap(payload[len(octet):], want)
		if err != nil {
			return nil, err
		}
		if len(plain) != want {
			return nil, fmt.Errorf("sealed part length %d, want %d", len(plain), want)
		}
		out.Write(plain)
	}
	return out.Bytes(), nil
}

func originalLength(header []byte) (int, error) {
	const marker = "Length="
	i := bytes.Index(header, []byte(marker))
	if i < 0 {
		return 0, fmt.Errorf("sealed response has no OriginalContent length")
	}
	v := header[i+len(marker):]
	if end := bytes.IndexAny(v, "\r\n \t"); end >= 0 {
		v = v[:end]
	}
	n, err := strconv.Atoi(string(v))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid OriginalContent length %q", v)
	}
	return n, nil
}
