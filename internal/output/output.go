// Package output centralizes terminal rendering so every component prints with
// the same colored, prefixed style.
package output

import (
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
)

// ANSI color codes, disabled automatically when stdout is not a TTY.
const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	bold   = "\033[1m"
)

// Printer writes colored, prefixed messages. The zero value is not usable; call
// New.
type Printer struct {
	color bool
}

// New returns a Printer. Colors are enabled only when stdout is a terminal.
func New() *Printer {
	return &Printer{color: isatty.IsTerminal(os.Stdout.Fd())}
}

func (p *Printer) paint(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + reset
}

// Banner prints the startup banner.
func (p *Printer) Banner(s string) {
	fmt.Fprintln(os.Stderr, p.paint(cyan+bold, s))
}

// Infof prints an informational message prefixed with a blue marker.
func (p *Printer) Infof(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", p.paint(blue, "[*]"), fmt.Sprintf(format, a...))
}

// Successf prints a success message prefixed with a green marker.
func (p *Printer) Successf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", p.paint(green, "[+]"), fmt.Sprintf(format, a...))
}

// Warnf prints a warning prefixed with a yellow marker.
func (p *Printer) Warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", p.paint(yellow, "[!]"), fmt.Sprintf(format, a...))
}

// Errorf prints an error prefixed with a red marker.
func (p *Printer) Errorf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", p.paint(red, "[-]"), fmt.Sprintf(format, a...))
}

// Prompt returns the colored interactive prompt for the given remote path.
func (p *Printer) Prompt(path string) string {
	return p.paint(yellow+bold, "evil-winrm-go") + p.paint(blue, " PS ") + p.paint(green, path+"> ")
}
