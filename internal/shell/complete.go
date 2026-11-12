package shell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/0xbbuddha/evil-winrm-go/internal/winrm"
)

var builtins = []string{"upload", "download", "script", "services", "menu", "exit", "quit", "cd"}

// completer finishes command names, local paths for upload/script, and remote
// paths for everything else that looks like a filesystem argument.
type completer struct {
	client *winrm.Client
}

func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	if pos > len(line) {
		pos = len(line)
	}
	before := string(line[:pos])
	token, command, argN := splitToken(before)
	switch {
	case argN == 0:
		return suffixes(token, filterPrefix(builtins, token)), pos
	case (command == "upload" || command == "script") && argN == 1:
		return suffixes(token, localPaths(token)), pos
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		matches, err := c.client.Complete(ctx, token)
		if err != nil {
			return nil, 0
		}
		return suffixes(token, matches), pos
	}
}

// splitToken reports the word under the cursor, the first word, and which
// argument that word is (0 is the command itself).
func splitToken(before string) (token, command string, argN int) {
	trailing := before != "" && unicode.IsSpace(rune(before[len(before)-1]))
	fields := strings.Fields(before)
	if len(fields) == 0 {
		return "", "", 0
	}
	command = strings.ToLower(fields[0])
	if trailing {
		return "", command, len(fields)
	}
	return fields[len(fields)-1], command, len(fields) - 1
}

func filterPrefix(words []string, prefix string) []string {
	var out []string
	for _, w := range words {
		if strings.HasPrefix(w, strings.ToLower(prefix)) {
			out = append(out, w)
		}
	}
	return out
}

func localPaths(partial string) []string {
	dir, leaf := filepath.Split(partial)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if leaf != "" && !strings.HasPrefix(strings.ToLower(e.Name()), strings.ToLower(leaf)) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			p += string(os.PathSeparator)
		}
		out = append(out, p)
	}
	return out
}

// suffixes returns what readline should append. The library writes the
// candidate after the text already on the line.
func suffixes(token string, matches []string) [][]rune {
	tr := []rune(token)
	var out [][]rune
	for _, m := range matches {
		mr := []rune(m)
		if len(mr) >= len(tr) && strings.EqualFold(string(mr[:len(tr)]), token) {
			out = append(out, mr[len(tr):])
			continue
		}
		out = append(out, mr)
	}
	return out
}
