package winrm

import (
	"fmt"
	"io"
	"net/http"
)

// soapEnvelope builds a WSMan request envelope for the PowerShell resource. It
// covers the headers a Create needs; Command/Receive add selectors on top.
func soapEnvelope(action, to, resourceURI, msgID, protocolVersion, body string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:To>%s</a:To><w:ResourceURI s:mustUnderstand="true">%s</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action s:mustUnderstand="true">%s</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize><a:MessageID>%s</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false"/><p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/><w:OptionSet s:mustUnderstand="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><w:Option Name="protocolversion" MustComply="true">%s</w:Option></w:OptionSet><w:OperationTimeout>PT60S</w:OperationTimeout></s:Header><s:Body>%s</s:Body></s:Envelope>`,
		to, resourceURI, action, msgID, protocolVersion, body)
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
