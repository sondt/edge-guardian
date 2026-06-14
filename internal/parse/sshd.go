package parse

import (
	"fmt"
	"regexp"
)

// sshFailedRe khớp phần đầu của dòng sshd báo đăng nhập thất bại (auth.log/journald):
//
//	Failed password for root from 1.2.3.4 port 54321 ssh2
//	Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2
//
// Group 1 = tiền tố "invalid user " (tùy chọn), group 2 = username.
var sshFailedRe = regexp.MustCompile(`Failed password for (invalid user )?(\S+) `)

// sshFromPortRe khớp mọi cụm "from <ip> port <n>" trên dòng.
var sshFromPortRe = regexp.MustCompile(`from (\S+) port \d+`)

// SSHParser trích IP + lý do từ dòng log sshd.
type SSHParser struct{}

// NewSSHParser tạo parser sshd (không cấu hình — pattern cố định, ổn định).
func NewSSHParser() *SSHParser { return &SSHParser{} }

// Parse trả về (ip, reason, true) nếu dòng là một lần đăng nhập SSH thất bại.
//
// Chống log-injection: username do client điều khiển; một kẻ tấn công có thể đặt
// username chứa "from <ip-nạn-nhân> port 22" để đổ vạ. sshd luôn nối cụm
// "from <ip-thật> port <n>" của chính nó vào CUỐI dòng, nên ta lấy cụm "from ... port"
// CUỐI CÙNG làm IP nguồn — không thể bị spoof bằng username.
func (p *SSHParser) Parse(line string) (ip, reason string, ok bool) {
	m := sshFailedRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	froms := sshFromPortRe.FindAllStringSubmatch(line, -1)
	if len(froms) == 0 {
		return "", "", false
	}
	ip = froms[len(froms)-1][1] // cụm "from ... port" cuối cùng = peer thật của sshd
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
