// psrp-spike opens a PSRP runspace over WSMan and prints the shell id, to
// validate the sealed-transport + go-psrpcore handshake against a live host.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/0xbbuddha/evil-winrm-go/internal/winrm"
)

func main() {
	host := flag.String("i", "", "target")
	port := flag.Int("P", 5985, "port")
	user := flag.String("u", "", "username")
	pass := flag.String("p", "", "password")
	hash := flag.String("H", "", "NT hash")
	flag.Parse()

	cfg := winrm.Config{
		Host:     *host,
		Port:     *port,
		Username: *user,
		Password: *pass,
		Hash:     *hash,
		Insecure: true,
		Timeout:  60 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := winrm.OpenPSRP(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer sess.Close()
	fmt.Println("runspace opened, ShellId:", sess.ShellID())
}
