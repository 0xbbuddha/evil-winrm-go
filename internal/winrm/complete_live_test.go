package winrm

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConnectTiming(t *testing.T) {
	pass := os.Getenv("EWRM_PASS")
	if pass == "" {
		t.Skip("set EWRM_PASS to time the lab connection")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5985", time.Second)
	if err != nil {
		t.Skip(err)
	}
	conn.Close()

	ctx := context.Background()
	cfg := Config{Host: "127.0.0.1", Port: 5985, Username: "msfadmin", Password: pass, Timeout: 30 * time.Second}

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if err := c.InitPath(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("prompt %s", time.Since(start))
	time.Sleep(300 * time.Millisecond)
	start = time.Now()
	if _, err := c.RunPS(ctx, "whoami"); err != nil {
		t.Fatal(err)
	}
	t.Logf("next command %s", time.Since(start))

	shot, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer shot.Close()
	start = time.Now()
	out, err := shot.RunFirst(ctx, "whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "msfadmin") {
		t.Fatalf("whoami %q", out)
	}
	t.Logf("oneshot %s", time.Since(start))
}

func TestCompleteLive(t *testing.T) {
	pass := os.Getenv("EWRM_PASS")
	if pass == "" {
		t.Skip("set EWRM_PASS to test completion against the lab")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5985", time.Second)
	if err != nil {
		t.Skip(err)
	}
	conn.Close()

	c, err := New(Config{Host: "127.0.0.1", Port: 5985, Username: "msfadmin", Password: pass, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.InitPath(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := c.Complete(ctx, `C:\Users\`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range got {
		if strings.Contains(strings.ToLower(m), "msfadmin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no msfadmin in %q", got)
	}
}

func TestCloseLive(t *testing.T) {
	pass := os.Getenv("EWRM_PASS")
	if pass == "" {
		t.Skip("set EWRM_PASS to test close latency against the lab")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:5985", time.Second)
	if err != nil {
		t.Skip(err)
	}
	conn.Close()

	c, err := New(Config{Host: "127.0.0.1", Port: 5985, Username: "msfadmin", Password: pass, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.InitPath(ctx); err != nil {
		t.Fatal(err)
	}
	// Sit at the prompt long enough for the idle Receive to be in flight.
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("close took %s", d)
	} else {
		t.Logf("close took %s", d)
	}
}
