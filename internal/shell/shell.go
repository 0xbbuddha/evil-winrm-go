// Package shell drives the interactive Evil-WinRM prompt: it reads lines,
// routes built-in menu commands, and forwards everything else to the remote
// PowerShell session.
package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"

	"github.com/0xbbuddha/evil-winrm-go/internal/output"
	"github.com/0xbbuddha/evil-winrm-go/internal/winrm"
)

// Shell holds the state of an interactive session.
type Shell struct {
	client *winrm.Client
	out    *output.Printer
	rl     *readline.Instance
}

// New creates a Shell bound to a connected client.
func New(client *winrm.Client, out *output.Printer) (*Shell, error) {
	rl, err := readline.NewEx(&readline.Config{
		HistoryFile:            "/tmp/.evil-winrm-go_history",
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
		DisableAutoSaveHistory: false,
		AutoComplete:           &completer{client: client},
	})
	if err != nil {
		return nil, err
	}
	return &Shell{client: client, out: out, rl: rl}, nil
}

// Close releases the readline resources.
func (s *Shell) Close() error { return s.rl.Close() }

// Run loops reading and executing commands until the user exits or input ends.
func (s *Shell) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		s.rl.SetPrompt(s.out.Prompt(s.client.Path()))
		line, err := s.rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			continue // Ctrl-C cancels the current line, not the session
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if stop := s.dispatch(ctx, line); stop {
			return nil
		}
	}
}

// dispatch handles one input line. It returns true when the session should end.
func (s *Shell) dispatch(ctx context.Context, line string) (stop bool) {
	fields := strings.Fields(line)
	switch strings.ToLower(fields[0]) {
	case "exit", "quit":
		return true
	case "menu":
		s.printMenu()
	case "upload":
		s.handleUpload(ctx, fields[1:])
	case "download":
		s.handleDownload(ctx, fields[1:])
	case "services":
		s.runRemote(ctx, servicesPS)
	case "script":
		s.handleScript(ctx, fields[1:])
	default:
		s.runRemote(ctx, line)
	}
	return false
}

// runRemote executes a PowerShell command remotely and prints its output.
func (s *Shell) runRemote(ctx context.Context, cmd string) {
	out, err := s.client.RunPS(ctx, cmd)
	if out != "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
	if err != nil {
		s.out.Errorf("%v", err)
	}
}

func (s *Shell) handleUpload(ctx context.Context, args []string) {
	if len(args) < 1 || len(args) > 2 {
		s.out.Warnf("usage: upload <local-file> [remote-file]")
		return
	}
	local := args[0]
	remote := ""
	if len(args) == 2 {
		remote = args[1]
	}
	s.out.Infof("uploading %s ...", local)
	if err := s.client.Upload(ctx, local, remote); err != nil {
		s.out.Errorf("upload failed: %v", err)
		return
	}
	s.out.Successf("uploaded %s", local)
}

func (s *Shell) handleDownload(ctx context.Context, args []string) {
	if len(args) < 1 || len(args) > 2 {
		s.out.Warnf("usage: download <remote-file> [local-file]")
		return
	}
	remote := args[0]
	local := args[0]
	if len(args) == 2 {
		local = args[1]
	} else if i := strings.LastIndexAny(local, "\\/"); i >= 0 {
		local = local[i+1:] // default to the base name in the current dir
	}
	s.out.Infof("downloading %s ...", remote)
	if err := s.client.Download(ctx, remote, local); err != nil {
		s.out.Errorf("download failed: %v", err)
		return
	}
	s.out.Successf("saved to %s", local)
}

func (s *Shell) handleScript(ctx context.Context, args []string) {
	if len(args) != 1 {
		s.out.Warnf("usage: script <local.ps1 | directory>")
		return
	}
	s.out.Infof("loading %s ...", args[0])
	out, err := s.client.LoadScripts(ctx, args[0])
	if out != "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
	if err != nil {
		s.out.Errorf("script failed: %v", err)
		return
	}
	s.out.Successf("loaded %s", args[0])
}

func (s *Shell) printMenu() {
	fmt.Println(`
evil-winrm-go menu:
  upload <local> [remote]       Upload a file to the target
  download <remote> [local]     Download a file from the target
  script <local.ps1 | dir>      Dot-source a local script into the session
  services                      List services and their binary paths
  menu                          Show this menu
  exit | quit                   Close the session

Anything else is executed as a PowerShell command on the target.`)
}

// servicesPS enumerates services with their start mode, state and binary path,
// a common first stop when hunting for privilege-escalation footholds.
const servicesPS = `Get-CimInstance Win32_Service | ` +
	`Select-Object Name, StartMode, State, StartName, PathName | Format-Table -AutoSize | Out-String -Width 4096`
