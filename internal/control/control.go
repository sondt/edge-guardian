// Package control provides a unix control socket that lets the CLI control the
// running daemon (currently: unban). The protocol is newline-delimited JSON, one
// request per connection.
//
// Security: the socket is created with mode 0600 (root read/write only) — matching the
// daemon-runs-as-root/CAP_NET_ADMIN model. There is no extra authentication; the file
// permissions are the boundary.
package control

// Request is a command sent to the daemon.
type Request struct {
	Cmd string `json:"cmd"`          // "unban" | "ping"
	IP  string `json:"ip,omitempty"` // for "unban"
}

// Response is the returned result.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
