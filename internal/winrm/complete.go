package winrm

import (
	"context"
	"fmt"
	"strings"
)

// Complete lists remote files and directories that continue partial. Directories
// come back with a trailing backslash so another Tab can descend into them.
func (c *Client) Complete(ctx context.Context, partial string) ([]string, error) {
	if c.sess == nil {
		return nil, nil
	}
	ps := fmt.Sprintf(`$p = %s
if ($p -eq '' -or $p.EndsWith('\') -or $p.EndsWith('/')) {
  $dir = $p
  if ($dir -eq '') { $dir = (Get-Location).Path }
  $leaf = ''
} else {
  $dir = Split-Path -Parent $p
  if (-not $dir) { $dir = (Get-Location).Path }
  $leaf = Split-Path -Leaf $p
}
Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue |
  Where-Object { $leaf -eq '' -or $_.Name.StartsWith($leaf, [StringComparison]::OrdinalIgnoreCase) } |
  ForEach-Object {
    if ($_.PSIsContainer) { $_.FullName + '\' } else { $_.FullName }
  }`, psQuote(partial))
	out, err := c.RunPS(ctx, ps)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			matches = append(matches, line)
		}
	}
	return matches, nil
}
