package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

// psSession is one powershell.exe kept alive over a WinRM shell. Commands are
// sent on its stdin and stay in the same process, so variables, functions and
// the working directory survive from one call to the next.
type psSession struct {
	shell  *winrm.Shell
	cmd    *winrm.Command
	marker string

	mu     sync.Mutex
	errMu  sync.Mutex
	errBuf bytes.Buffer
}

// openSession starts the persistent PowerShell and records its initial
// directory (the user's Documents folder when that folder exists). first, when
// set, runs inside that same startup, before any idle Receive can delay it.
func (c *Client) openSession(ctx context.Context, first string) (string, error) {
	if c.sess != nil {
		if first == "" {
			return "", nil
		}
		out, _, err := c.sess.exec(ctx, first)
		return out, err
	}
	marker, err := randToken()
	if err != nil {
		return "", err
	}
	encoded := winrm.Powershell(sessionScript(marker, first))
	const prefix = "powershell.exe -EncodedCommand "
	if !strings.HasPrefix(encoded, prefix) || len(encoded) == len(prefix) {
		return "", fmt.Errorf("encode persistent powershell")
	}

	shell, err := c.wc.CreateShell()
	if err != nil {
		return "", fmt.Errorf("open shell: %w", err)
	}
	cmd, err := shell.ExecuteWithContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded[len(prefix):])
	if err != nil {
		_ = shell.Close()
		return "", fmt.Errorf("start powershell: %w", err)
	}

	s := &psSession{shell: shell, cmd: cmd, marker: marker}
	go s.drainErr()
	c.sess = s

	start, cancel := context.WithTimeout(ctx, 45*time.Second)
	out, path, err := s.readFrame(start)
	cancel()
	_ = s.takeErr()
	if err != nil {
		s.close()
		c.sess = nil
		return out, fmt.Errorf("persistent powershell: %w", err)
	}
	if path == "" {
		s.close()
		c.sess = nil
		return out, fmt.Errorf("persistent powershell returned no working directory")
	}
	c.path = path
	return out, nil
}

// Close ends the session. While the prompt is idle, a WinRM Receive already
// owns the only NTLM connection and will not return until its operation
// timeout (about two seconds). Closing the socket unblocks that call.
// Sending Signal or DeleteShell afterwards would dial a new connection and
// authenticate again, which is the wait exit used to pay.
func (c *Client) Close() error {
	if c.conns != nil && c.conns.drop() {
		c.sess = nil
		return nil
	}
	if c.sess == nil {
		return nil
	}
	c.sess.close()
	c.sess = nil
	return nil
}

func (s *psSession) close() {
	if s.cmd != nil {
		_ = s.cmd.Stdin.Close()
		_ = s.cmd.Close()
	}
	if s.shell != nil {
		_ = s.shell.Close()
	}
}

// exec sends one command and returns its output plus the directory afterwards.
func (s *psSession) exec(ctx context.Context, command string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(command) == "" {
		return "", "", nil
	}
	line := base64.StdEncoding.EncodeToString([]byte(command)) + "\n"
	if _, err := s.cmd.Stdin.Write([]byte(line)); err != nil {
		return "", "", fmt.Errorf("send command: %w", err)
	}
	out, path, err := s.readFrame(ctx)
	if extra := strings.TrimSpace(s.takeErr()); extra != "" {
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += extra + "\n"
	}
	if err != nil {
		return out, path, err
	}
	return out, path, nil
}

// readFrame reads stdout until the session marker and the path that follows it.
func (s *psSession) readFrame(ctx context.Context) (string, string, error) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.cmd.Close()
		case <-done:
		}
	}()

	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return buf.String(), "", err
		}
		n, err := s.cmd.Stdout.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if out, path, ok := splitFrame(buf.Bytes(), s.marker); ok {
				return out, path, nil
			}
		}
		if err != nil {
			return buf.String(), "", err
		}
	}
}

func (s *psSession) drainErr() {
	tmp := make([]byte, 1024)
	for {
		n, err := s.cmd.Stderr.Read(tmp)
		if n > 0 {
			s.errMu.Lock()
			s.errBuf.Write(tmp[:n])
			s.errMu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (s *psSession) takeErr() string {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	b := s.errBuf.String()
	s.errBuf.Reset()
	return b
}

// splitFrame reports the command output and the working directory once marker
// and the path line that follows it have both arrived.
func splitFrame(buf []byte, marker string) (out, path string, ok bool) {
	i := bytes.LastIndex(buf, []byte(marker))
	if i < 0 {
		return "", "", false
	}
	rest := buf[i+len(marker):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return "", "", false
	}
	return string(buf[:i]), strings.TrimSpace(string(rest[:nl])), true
}

// sessionScript is the PowerShell program that stays running. The marker is
// printed after every command so the client knows where the output ends.
func sessionScript(marker, first string) string {
	var prelude string
	if first != "" {
		prelude = fmt.Sprintf(`try {
  $s = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
  $r = Invoke-Expression $s *>&1 | Out-String -Width 4096
  if ($r) { [Console]::Out.Write($r) }
} catch {
  [Console]::Out.WriteLine($_.Exception.Message)
}
`, base64.StdEncoding.EncodeToString([]byte(first)))
	}
	return fmt.Sprintf(`$__ew = %s
function global:__ewrm_end {
  [Console]::Out.WriteLine($__ew + (Get-Location).Path)
  [Console]::Out.Flush()
}
$d = [Environment]::GetFolderPath('MyDocuments')
if ($d -and (Test-Path -LiteralPath $d)) { Set-Location -LiteralPath $d }
%s__ewrm_end
$__in = New-Object System.IO.StreamReader ([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8)
while ($true) {
  $l = $__in.ReadLine()
  if ($null -eq $l) { break }
  if ($l -eq '') { __ewrm_end; continue }
  try {
    $s = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($l))
    $r = Invoke-Expression $s *>&1 | Out-String -Width 4096
    if ($r) { [Console]::Out.Write($r) }
  } catch {
    [Console]::Out.WriteLine($_.Exception.Message)
  }
  __ewrm_end
}
`, psQuote(marker), prelude)
}
