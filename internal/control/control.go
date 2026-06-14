// Package control cung cấp một unix control socket để CLI điều khiển daemon đang
// chạy (hiện tại: unban). Giao thức là JSON theo dòng (newline-delimited), một
// request mỗi kết nối.
//
// Bảo mật: socket được tạo với quyền 0600 (chỉ root đọc/ghi) — phù hợp với mô hình
// daemon chạy root/CAP_NET_ADMIN. Không có xác thực thêm; quyền file là ranh giới.
package control

// Request là lệnh gửi tới daemon.
type Request struct {
	Cmd string `json:"cmd"`          // "unban" | "ping"
	IP  string `json:"ip,omitempty"` // cho "unban"
}

// Response là kết quả trả về.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
