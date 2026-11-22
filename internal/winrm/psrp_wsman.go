package winrm

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// soapEnvelope builds a WSMan request envelope for the PowerShell resource.
// selectors (a <w:SelectorSet>) and optionSet (a <w:OptionSet>) are header
// fragments, either of which may be empty.
func soapEnvelope(action, to, resourceURI, msgID, selectors, optionSet, body string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:To>%s</a:To><w:ResourceURI s:mustUnderstand="true">%s</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">%s</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>%s</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>%s%s<w:OperationTimeout>PT60S</w:OperationTimeout></s:Header><s:Body>%s</s:Body></s:Envelope>`,
		to, resourceURI, action, msgID, selectors, optionSet, body)
}

func protocolOptionSet(version string) string {
	return `<w:OptionSet s:mustUnderstand="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><w:Option Name="protocolversion" MustComply="true">` + version + `</w:Option></w:OptionSet>`
}

func (s *PSRPSession) shellSelector() string {
	return `<w:SelectorSet><w:Selector Name="ShellId">` + s.shellID + `</w:Selector></w:SelectorSet>`
}

// command sends a CREATE_PIPELINE payload as the arguments of a WSMan Command
// and returns the server-assigned CommandId.
func (s *PSRPSession) command(ctx context.Context, argsB64 string) (string, error) {
	body := `<rsp:CommandLine xmlns:rsp="` + wsmanNsShell + `"><rsp:Command></rsp:Command><rsp:Arguments>` + argsB64 + `</rsp:Arguments></rsp:CommandLine>`
	env := soapEnvelope(wsmanActionCommand, s.url, wsmanResourcePowerShell, msgUUID(), s.shellSelector(), "", body)
	resp, err := s.post(ctx, env)
	if err != nil {
		return "", err
	}
	var cr struct {
		CommandID string `xml:"Body>CommandResponse>CommandId"`
	}
	if err := xml.Unmarshal(resp, &cr); err != nil {
		return "", fmt.Errorf("parse command response: %w", err)
	}
	if cr.CommandID == "" {
		return "", fmt.Errorf("command response had no CommandId: %s", snippet(resp))
	}
	return cr.CommandID, nil
}

// receive polls WSMan Receive for cmdID (empty for the pool stream) and returns
// the decoded stdout bytes plus whether the command/pool reached Done.
func (s *PSRPSession) receive(ctx context.Context, cmdID string) ([]byte, bool, error) {
	desired := `<rsp:DesiredStream>stdout</rsp:DesiredStream>`
	if cmdID != "" {
		desired = `<rsp:DesiredStream CommandId="` + cmdID + `">stdout</rsp:DesiredStream>`
	}
	body := `<rsp:Receive xmlns:rsp="` + wsmanNsShell + `">` + desired + `</rsp:Receive>`
	env := soapEnvelope(wsmanActionReceive, s.url, wsmanResourcePowerShell, msgUUID(), s.shellSelector(), "", body)
	resp, err := s.post(ctx, env)
	if err != nil {
		return nil, false, err
	}
	var rr struct {
		Streams []struct {
			Data string `xml:",chardata"`
		} `xml:"Body>ReceiveResponse>Stream"`
		CommandState struct {
			State string `xml:"State,attr"`
		} `xml:"Body>ReceiveResponse>CommandState"`
	}
	if err := xml.Unmarshal(resp, &rr); err != nil {
		return nil, false, fmt.Errorf("parse receive response: %w", err)
	}
	var data []byte
	for _, st := range rr.Streams {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(st.Data))
		if err != nil {
			return nil, false, fmt.Errorf("decode receive stream: %w", err)
		}
		data = append(data, b...)
	}
	return data, strings.HasSuffix(rr.CommandState.State, "/Done"), nil
}

// send delivers PSRP fragment bytes to a stream (stdin) of cmdID via WSMan Send.
func (s *PSRPSession) send(ctx context.Context, cmdID string, p []byte) error {
	cmdAttr := ""
	if cmdID != "" {
		cmdAttr = ` CommandId="` + cmdID + `"`
	}
	body := `<rsp:Send xmlns:rsp="` + wsmanNsShell + `"><rsp:Stream Name="stdin"` + cmdAttr + `>` + base64.StdEncoding.EncodeToString(p) + `</rsp:Stream></rsp:Send>`
	env := soapEnvelope(wsmanActionSend, s.url, wsmanResourcePowerShell, msgUUID(), s.shellSelector(), "", body)
	_, err := s.post(ctx, env)
	return err
}

func readAll(resp *http.Response) ([]byte, error) {
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return b, nil
}

// snippet truncates a response for error messages.
func snippet(b []byte) string {
	const max = 2500
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
