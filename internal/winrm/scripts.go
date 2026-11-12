package winrm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadScripts dot-sources a local .ps1 file, or every .ps1 in a directory, into
// the remote session. The file is uploaded to C:\Windows\Temp and then sourced,
// so functions it defines stay available for later commands.
func (c *Client) LoadScripts(ctx context.Context, local string) (string, error) {
	info, err := os.Stat(local)
	if err != nil {
		return "", fmt.Errorf("script %s: %w", local, err)
	}
	if !info.IsDir() {
		return c.loadScript(ctx, local)
	}

	entries, err := os.ReadDir(local)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".ps1") {
			continue
		}
		out, err := c.loadScript(ctx, filepath.Join(local, e.Name()))
		b.WriteString(out)
		if err != nil {
			return b.String(), err
		}
		n++
	}
	if n == 0 {
		return "", fmt.Errorf("no .ps1 files in %s", local)
	}
	return b.String(), nil
}

func (c *Client) loadScript(ctx context.Context, local string) (string, error) {
	remote := `C:\Windows\Temp\` + filepath.Base(local)
	if err := c.Upload(ctx, local, remote); err != nil {
		return "", fmt.Errorf("upload script: %w", err)
	}
	c.scripts = append(c.scripts, remote)
	// One import is enough: the persistent process keeps the functions.
	expr := fmt.Sprintf("Invoke-Expression -Command ([IO.File]::ReadAllText(%s))", psQuote(remote))
	out, err := c.RunPS(ctx, expr)
	if err != nil {
		return out, fmt.Errorf("load %s: %w", filepath.Base(local), err)
	}
	return out, nil
}
