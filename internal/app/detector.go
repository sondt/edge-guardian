package app

import "github.com/sondt/edge-guardian/internal/detect"

// Detector là một nguồn phát hiện: nó soi từng dòng log, nếu là "hit" thì trả về IP,
// một khóa con tùy chọn (sub), và lý do; rồi đếm theo Counter riêng trước khi quyết
// định ban.
//
//   - sub rỗng + Counter là Hits → đếm số sự kiện (HTTP/SSH/honeypot).
//   - sub = port + Counter là Distinct → đếm số PORT distinct (port scan).
//
// Các detector dùng pattern rời nhau, nên mỗi dòng chỉ khớp một detector — daemon chạy
// mọi detector trên mọi dòng, không cần định tuyến theo file. Thêm nguồn mới = thêm một
// Detector, không sửa pipeline.
type Detector struct {
	Name    string
	Inspect func(line string) (ip, sub, reason string, ok bool)
	Window  detect.Counter
}
