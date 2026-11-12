// evil-winrm-go is a WinRM shell for pentesting, a Go take on the classic
// evil-winrm. It opens a semi-interactive PowerShell session over WinRM with
// NTLM password auth or pass-the-hash, plus file upload/download helpers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/0xbbuddha/evil-winrm-go/internal/output"
	"github.com/0xbbuddha/evil-winrm-go/internal/shell"
	"github.com/0xbbuddha/evil-winrm-go/internal/winrm"
)

const banner = `
▄███▄      ▄   ▄█ █           ▄ ▄   ▄█    ▄   █▄▄▄▄ █▀▄▀█       ▄▀  ████▄
█▀   ▀      █  ██ █          █   █  ██     █  █  ▄▀ █ █ █     ▄▀    █   █
██▄▄   █     █ ██ █      ▬▬ █ ▄   █ ██ ██   █ █▀▀▌  █ ▄ █  ▬▬ █ ▀▄  █   █
█▄   ▄▀ █    █ ▐█ ███▄      █  █  █ ▐█ █ █  █ █  █  █   █     █   █ ▀████
▀███▀    █  █   ▐     ▀      █ █ █   ▐ █  █ █   █      █       ███
          █▐                  ▀ ▀      █   ██  ▀      ▀
          ▐`

func main() {
	var (
		host     = flag.String("i", "", "target IP or hostname")
		port     = flag.Int("P", 0, "WinRM port (default 5985, or 5986 with -S)")
		user     = flag.String("u", "", "username")
		pass     = flag.String("p", "", "password")
		hash     = flag.String("H", "", "NT hash for pass-the-hash")
		domain   = flag.String("d", "", "domain (NTLM: NetBIOS domain)")
		ssl      = flag.Bool("S", false, "use HTTPS/SSL")
		insecure = flag.Bool("k", true, "skip TLS certificate verification")
		command  = flag.String("c", "", "run a single command then exit")
		targets  = flag.String("targets", "", "file of hosts (one per line) to run -c against")
		threads  = flag.Int("threads", 8, "parallel connections for -targets")
		scripts  = flag.String("s", "", "local .ps1 file or directory to dot-source after connect")
		kerberos = flag.Bool("kerberos", false, "authenticate with Kerberos")
		realm    = flag.String("realm", "", "Kerberos realm")
		spn      = flag.String("spn", "", "Kerberos SPN (default HTTP/<host>)")
		ccache   = flag.String("ccache", "", "Kerberos credential cache (default $KRB5CCNAME)")
		krb5conf = flag.String("krb5conf", "/etc/krb5.conf", "path to krb5.conf")
		certFile = flag.String("cert", "", "client certificate PEM (requires -S)")
		keyFile  = flag.String("key", "", "client private key PEM (requires -S)")
		caFile   = flag.String("cacert", "", "CA certificate PEM used to verify the server")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\nUsage: %s -i <host> [-u <user>] [-p <pass> | -H <hash> | -kerberos | -cert <pem>] [flags]\n\nFlags:\n", banner, os.Args[0])
		printFlags()
	}
	flag.Parse()

	if *targets == "" && *host == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *targets != "" && *host != "" {
		fmt.Fprintln(os.Stderr, "error: use either -i or -targets")
		os.Exit(2)
	}
	if *targets != "" && *command == "" {
		fmt.Fprintln(os.Stderr, "error: -targets needs a command (-c)")
		os.Exit(2)
	}

	ca, err := readOptional(*caFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	cfg := winrm.Config{
		Host:      *host,
		Port:      resolvePort(*port, *ssl),
		HTTPS:     *ssl,
		Insecure:  *insecure,
		Username:  *user,
		Password:  *pass,
		Hash:      normalizeHash(*hash),
		Domain:    *domain,
		CACert:    ca,
		Timeout:   180 * time.Second,
		Kerberos:  *kerberos,
		Realm:     *realm,
		SPN:       *spn,
		CCache:    resolveCCache(*kerberos, *ccache),
		KrbConfig: *krb5conf,
		CertFile:  *certFile,
		KeyFile:   *keyFile,
	}

	out := output.New()
	out.Banner(banner)

	if *targets != "" {
		if err := runTargets(cfg, out, *targets, *command, *scripts, *threads); err != nil {
			out.Errorf("%v", err)
			os.Exit(1)
		}
		return
	}
	if err := run(cfg, out, *command, *scripts); err != nil {
		out.Errorf("%v", err)
		os.Exit(1)
	}
}

// printFlags writes one line per flag: the flag, its type, then the description.
func printFlags() {
	type line struct{ flag, text string }
	var lines []line
	flag.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		label := "-" + f.Name
		if name != "" {
			label += " " + name
		}
		switch f.DefValue {
		case "", "0", "false", "0s":
		default:
			if name == "string" {
				usage = fmt.Sprintf("%s (default %q)", usage, f.DefValue)
			} else {
				usage = fmt.Sprintf("%s (default %s)", usage, f.DefValue)
			}
		}
		lines = append(lines, line{label, usage})
	})
	width := 0
	for _, l := range lines {
		if len(l.flag) > width {
			width = len(l.flag)
		}
	}
	for _, l := range lines {
		fmt.Fprintf(os.Stderr, "  %-*s  %s\n", width, l.flag, l.text)
	}
}

func run(cfg winrm.Config, out *output.Printer, oneShot, scripts string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := winrm.New(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	out.Infof("connecting to %s:%d (ssl=%t)", cfg.Host, cfg.Port, cfg.HTTPS)
	// A one-shot with no scripts runs inside the PowerShell that opens the session.
	if oneShot != "" && scripts == "" {
		o, err := client.RunFirst(ctx, oneShot)
		if err != nil {
			return fmt.Errorf("%s", winrm.Explain(err))
		}
		out.Successf("authenticated as %s", client.Identity())
		fmt.Print(o)
		if o != "" && !strings.HasSuffix(o, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := client.InitPath(ctx); err != nil {
		return fmt.Errorf("%s", winrm.Explain(err))
	}
	out.Successf("authenticated as %s", client.Identity())

	if scripts != "" {
		out.Infof("loading %s", scripts)
		o, err := client.LoadScripts(ctx, scripts)
		if o != "" {
			fmt.Print(o)
		}
		if err != nil {
			return fmt.Errorf("load scripts: %w", err)
		}
	}

	if oneShot != "" {
		o, err := client.RunPS(ctx, oneShot)
		fmt.Print(o)
		if !strings.HasSuffix(o, "\n") {
			fmt.Println()
		}
		return err
	}

	sh, err := shell.New(client, out)
	if err != nil {
		return err
	}
	defer sh.Close()
	return sh.Run(ctx)
}

// runTargets runs command on every host in the file, several at a time.
// Each host gets its own connection. Output is grouped under a host header.
// A failure on one host does not stop the others.
func runTargets(base winrm.Config, out *output.Printer, path, command, scripts string, threads int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	targets, err := winrm.ParseTargets(f)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no hosts in %s", path)
	}
	if threads < 1 {
		threads = 1
	}
	if threads > len(targets) {
		threads = len(targets)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	out.Infof("%d hosts, %d at a time", len(targets), threads)

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for _, t := range targets {
		wg.Add(1)
		go func(t winrm.Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			cfg := base
			cfg.Host = t.Host
			if t.Port != 0 {
				cfg.Port = t.Port
			}
			text, err := runOne(ctx, cfg, command, scripts)
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(os.Stderr, "\n===== %s =====\n", t.Raw)
			if err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "error: %s\n", winrm.Explain(err))
			}
			if text != "" {
				fmt.Fprint(os.Stderr, text)
				if !strings.HasSuffix(text, "\n") {
					fmt.Fprintln(os.Stderr)
				}
			}
		}(t)
	}
	wg.Wait()
	if failed > 0 {
		return fmt.Errorf("%d/%d hosts failed", failed, len(targets))
	}
	return nil
}

func runOne(ctx context.Context, cfg winrm.Config, command, scripts string) (string, error) {
	client, err := winrm.New(cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	if scripts == "" {
		o, err := client.RunFirst(ctx, command)
		if err != nil {
			return o, errors.New(winrm.Explain(err))
		}
		return o, nil
	}
	if err := client.InitPath(ctx); err != nil {
		return "", errors.New(winrm.Explain(err))
	}
	var b strings.Builder
	if scripts != "" {
		o, err := client.LoadScripts(ctx, scripts)
		b.WriteString(o)
		if err != nil {
			return b.String(), err
		}
	}
	o, err := client.RunPS(ctx, command)
	b.WriteString(o)
	return b.String(), err
}

// resolvePort returns the user-specified port, or the WinRM default for the
// chosen transport.
func resolvePort(port int, ssl bool) int {
	if port != 0 {
		return port
	}
	if ssl {
		return 5986
	}
	return 5985
}

// resolveCCache returns the credential cache to use. An explicit -ccache wins;
// otherwise Kerberos falls back to KRB5CCNAME. A FILE: prefix is stripped.
func resolveCCache(kerberos bool, flagValue string) string {
	cc := flagValue
	if cc == "" && kerberos {
		cc = os.Getenv("KRB5CCNAME")
	}
	return strings.TrimPrefix(cc, "FILE:")
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

// normalizeHash accepts "LM:NT" or a bare NT hash and returns the NT portion.
func normalizeHash(h string) string {
	if h == "" {
		return ""
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[i+1:]
	}
	return h
}
