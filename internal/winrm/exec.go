package winrm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// chunkSize bounds how many base64 characters ride in a single Add-Content call
// during uploads, keeping each WinRM command well under the command-line limit.
const chunkSize = 3000

// InitPath queries the remote working directory and stores it as the shell's
// current location. Like the Ruby and Python evil-winrm shells, it starts in
// the user's Documents folder when that folder exists. Call it once after
// connecting.
func (c *Client) InitPath(ctx context.Context) error {
	_, err := c.openSession(ctx, "")
	return err
}

// RunFirst opens the session and runs command in that same PowerShell start.
// A one-shot then costs one process and does not wait on an idle Receive.
func (c *Client) RunFirst(ctx context.Context, command string) (string, error) {
	return c.openSession(ctx, command)
}

// Path returns the current remote working directory.
func (c *Client) Path() string { return c.path }

// RunPS runs userCmd in the persistent PowerShell process when it is up, so
// variables and functions survive until the session closes. The working
// directory is tracked from the marker that process prints after every command.
func (c *Client) RunPS(ctx context.Context, userCmd string) (string, error) {
	if c.sess != nil {
		out, path, err := c.sess.exec(ctx, userCmd)
		if path != "" {
			c.path = path
		}
		return out, err
	}
	return c.runPSOnce(ctx, userCmd)
}

// runPSOnce runs userCmd in a fresh powershell.exe. Used before the persistent
// session exists, and as the behavior RunPS had originally.
func (c *Client) runPSOnce(ctx context.Context, userCmd string) (string, error) {
	sentinel, err := randToken()
	if err != nil {
		return "", err
	}
	wrapped := fmt.Sprintf(
		"Set-Location -LiteralPath %s;\n%s%s\n[Console]::Out.Write('%s');[Console]::Out.Write((Get-Location).Path)",
		psQuote(c.path), c.scriptPrelude(), userCmd, sentinel,
	)

	stdout, stderr, _, err := c.run(ctx, wrapped)
	if err != nil {
		return stdout, err
	}

	out := stdout
	if i := strings.LastIndex(out, sentinel); i >= 0 {
		if p := strings.TrimSpace(out[i+len(sentinel):]); p != "" {
			c.path = p
		}
		out = out[:i]
	}
	if stderr != "" {
		out += stderr
	}
	return out, nil
}

// Download fetches remote and writes it to local. The file is transferred as
// base64 to survive the text-only WinRM channel.
func (c *Client) Download(ctx context.Context, remote, local string) error {
	ps := fmt.Sprintf(
		"if (Test-Path -LiteralPath %[1]s -PathType Leaf) { [Console]::Out.Write([Convert]::ToBase64String([IO.File]::ReadAllBytes(%[1]s))) } else { [Console]::Error.Write('NOFILE') }",
		psQuote(c.absRemote(remote)),
	)
	stdout, stderr, _, err := c.run(ctx, ps)
	if err != nil {
		return err
	}
	if strings.Contains(stderr, "NOFILE") {
		return fmt.Errorf("remote file not found: %s", remote)
	}
	if stderr != "" {
		return fmt.Errorf("remote error: %s", strings.TrimSpace(stderr))
	}
	data, err := base64.StdEncoding.DecodeString(stripSpace(stdout))
	if err != nil {
		return fmt.Errorf("decode remote content: %w", err)
	}
	return os.WriteFile(local, data, 0o600)
}

// Upload reads local and writes it to remote by streaming base64 chunks into a
// temporary file, then decoding it server-side.
func (c *Client) Upload(ctx context.Context, local, remote string) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	dst := c.absRemote(remote)
	// Unique name so two parallel uploads of the same file (for example
	// -targets hitting one host twice) do not share the temp file.
	n := make([]byte, 4)
	if _, err := rand.Read(n); err != nil {
		return err
	}
	tmp := dst + "." + hex.EncodeToString(n) + ".b64"

	// Start from a clean temp file.
	if _, stderr, _, err := c.run(ctx, fmt.Sprintf("Remove-Item -LiteralPath %s -ErrorAction SilentlyContinue", psQuote(tmp))); err != nil {
		return err
	} else if strings.TrimSpace(stderr) != "" {
		return fmt.Errorf("prepare upload: %s", strings.TrimSpace(stderr))
	}

	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		verb := "Add-Content"
		if i == 0 {
			verb = "Set-Content"
		}
		ps := fmt.Sprintf("%s -LiteralPath %s -Value %s -Encoding Ascii -NoNewline", verb, psQuote(tmp), psQuote(encoded[i:end]))
		if _, stderr, _, err := c.run(ctx, ps); err != nil {
			return err
		} else if strings.TrimSpace(stderr) != "" {
			return fmt.Errorf("upload chunk: %s", strings.TrimSpace(stderr))
		}
	}

	decode := fmt.Sprintf(
		"[IO.File]::WriteAllBytes(%[1]s, [Convert]::FromBase64String((Get-Content -LiteralPath %[2]s -Raw))); Remove-Item -LiteralPath %[2]s -Force",
		psQuote(dst), psQuote(tmp),
	)
	if _, stderr, _, err := c.run(ctx, decode); err != nil {
		return err
	} else if strings.TrimSpace(stderr) != "" {
		return fmt.Errorf("finalize upload: %s", strings.TrimSpace(stderr))
	}
	return nil
}

// scriptPrelude re-imports every script loaded with LoadScripts. Each RunPS
// starts a fresh powershell.exe, so functions only survive if they are defined
// again at the start of the next command. Invoke-Expression reads the uploaded
// file as text, which the default Restricted execution policy still allows.
func (c *Client) scriptPrelude() string {
	if len(c.scripts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, remote := range c.scripts {
		fmt.Fprintf(&b, "Invoke-Expression -Command ([IO.File]::ReadAllText(%s))\n", psQuote(remote))
	}
	return b.String()
}

// absRemote resolves a possibly-relative remote path against the current remote
// working directory.
func (c *Client) absRemote(p string) string {
	if p == "" {
		return c.path
	}
	if strings.Contains(p, ":\\") || strings.HasPrefix(p, "\\\\") {
		return p // already absolute (drive-qualified or UNC)
	}
	return strings.TrimRight(c.path, "\\") + "\\" + p
}

// psQuote renders s as a PowerShell single-quoted string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// stripSpace removes all whitespace, which WinRM may inject into long base64
// payloads.
func stripSpace(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(s)
}

// randToken returns a random hex marker used to delimit command output.
func randToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "@@EWRM_" + hex.EncodeToString(b) + "@@", nil
}
