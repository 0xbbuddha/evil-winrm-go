package winrm

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

// Target is one host from a -targets file. Port 0 means "use the default".
type Target struct {
	Host string
	Port int
	Raw  string
}

// ParseTargets reads hosts, one per line. Blank lines and lines starting with
// '#' are ignored. A trailing ":port" overrides the default WinRM port.
func ParseTargets(r io.Reader) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, port := splitTarget(line)
		out = append(out, Target{Host: host, Port: port, Raw: line})
	}
	return out, sc.Err()
}

func splitTarget(line string) (string, int) {
	if h, p, err := net.SplitHostPort(line); err == nil {
		n, err := strconv.Atoi(p)
		if err == nil {
			return h, n
		}
	}
	return line, 0
}
