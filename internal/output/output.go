// Package output centralizes terminal rendering so every component prints with
// the same colored, prefixed style.
package output

import (
	"fmt"
	"io"
	"os"
	"strings"

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
	log   io.Writer
}

// New returns a Printer. Colors are enabled only when stdout is a terminal.
func New() *Printer {
	return &Printer{color: isatty.IsTerminal(os.Stdout.Fd())}
}

// LogTo tees the session transcript (status lines, commands and output,
// without ANSI color) to w. Passing nil disables logging.
func (p *Printer) LogTo(w io.Writer) { p.log = w }

func (p *Printer) logLine(s string) {
	if p.log != nil {
		fmt.Fprintln(p.log, s)
	}
}

// emit prints a prefixed message to stderr and, when logging, the same line
// without color to the log.
func (p *Printer) emit(code, marker, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "%s %s\n", p.paint(code, marker), msg)
	p.logLine(marker + " " + msg)
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
func (p *Printer) Infof(format string, a ...any) { p.emit(blue, "[*]", format, a...) }

// Successf prints a success message prefixed with a green marker.
func (p *Printer) Successf(format string, a ...any) { p.emit(green, "[+]", format, a...) }

// Warnf prints a warning prefixed with a yellow marker.
func (p *Printer) Warnf(format string, a ...any) { p.emit(yellow, "[!]", format, a...) }

// Errorf prints an error prefixed with a red marker.
func (p *Printer) Errorf(format string, a ...any) { p.emit(red, "[-]", format, a...) }

// Output prints command output to stdout and the log, ensuring a trailing
// newline. It centralizes the "print then pad a newline" the callers repeated.
func (p *Printer) Output(s string) {
	if s == "" {
		return
	}
	fmt.Print(s)
	if !strings.HasSuffix(s, "\n") {
		fmt.Println()
	}
	if p.log != nil {
		fmt.Fprint(p.log, s)
		if !strings.HasSuffix(s, "\n") {
			fmt.Fprintln(p.log)
		}
	}
}

// LogCommand records an entered command line in the transcript. It is written
// to the log only, since the terminal already showed it as the user typed.
func (p *Printer) LogCommand(path, line string) {
	p.logLine("evil-winrm-go PS " + path + "> " + line)
}

// Prompt returns the colored interactive prompt for the given remote path.
func (p *Printer) Prompt(path string) string {
	return p.paint(yellow+bold, "evil-winrm-go") + p.paint(blue, " PS ") + p.paint(green, path+"> ")
}
