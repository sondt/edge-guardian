package parse

import (
	"fmt"
	"regexp"
)

// sshFailedRe matches the start of an sshd failed-login line (auth.log/journald):
//
//	Failed password for root from 1.2.3.4 port 54321 ssh2
//	Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2
//
// Group 1 = optional "invalid user " prefix, group 2 = username.
var sshFailedRe = regexp.MustCompile(`Failed password for (invalid user )?(\S+) `)

// sshFromPortRe matches every "from <ip> port <n>" segment on the line.
var sshFromPortRe = regexp.MustCompile(`from (\S+) port \d+`)

// SSHParser extracts IP + reason from an sshd log line.
type SSHParser struct{}

// NewSSHParser creates an sshd parser (no configuration — the pattern is fixed and stable).
func NewSSHParser() *SSHParser { return &SSHParser{} }

// Parse returns (ip, reason, true) if the line is a failed SSH login.
//
// Log-injection defense: the username is client-controlled; an attacker could set a
// username containing "from <victim-ip> port 22" to frame someone. sshd always appends its own
// "from <real-ip> port <n>" segment at the END of the line, so we take the LAST "from ... port"
// segment as the source IP — it cannot be spoofed via the username.
func (p *SSHParser) Parse(line string) (ip, reason string, ok bool) {
	m := sshFailedRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	froms := sshFromPortRe.FindAllStringSubmatch(line, -1)
	if len(froms) == 0 {
		return "", "", false
	}
	ip = froms[len(froms)-1][1] // last "from ... port" segment = sshd's real peer
	if ip == "" {
		return "", "", false
	}
	invalid := m[1] != ""
	user := m[2]
	if invalid {
		reason = fmt.Sprintf("ssh: failed password (invalid user %s)", user)
	} else {
		reason = fmt.Sprintf("ssh: failed password (user %s)", user)
	}
	return ip, reason, true
}
