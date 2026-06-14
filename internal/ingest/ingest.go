// Package ingest theo dõi nhiều file log (kèm log rotation) và đẩy từng dòng mới
// về một channel chung.
package ingest

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/nxadm/tail"
)

// Line là một dòng log kèm nguồn gốc của nó.
type Line struct {
	Source string
	Text   string
}

// Tailer theo dõi một tập file log.
type Tailer struct {
	paths []string
}

// New tạo Tailer cho các đường dẫn cho trước.
func New(paths []string) *Tailer {
	cp := make([]string, len(paths))
	copy(cp, paths)
	return &Tailer{paths: cp}
}

// Run bắt đầu tail mọi file, gửi dòng mới vào kênh trả về cho tới khi ctx hủy.
// Mỗi file chạy trong một goroutine riêng. Kênh được đóng khi mọi tailer dừng.
func (t *Tailer) Run(ctx context.Context) (<-chan Line, error) {
	out := make(chan Line, 1024)

	tails := make([]*tail.Tail, 0, len(t.paths))
	for _, p := range t.paths {
		tl, err := tail.TailFile(p, tail.Config{
			Follow: true,
			ReOpen: true, // theo dõi rotation
			// Bắt đầu từ CUỐI file: chỉ xử lý dòng MỚI. Tránh việc khi daemon khởi
			// động/restart lại quét toàn bộ log lịch sử và ban hàng loạt IP cũ (mỗi
			// match được đóng dấu thời gian "now" khi đọc). Sau rotation, file mới
			// được đọc từ đầu nên không bỏ sót dòng.
			Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
			MustExist: false,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			for _, opened := range tails {
				_ = opened.Stop()
			}
			return nil, fmt.Errorf("tail %q: %w", p, err)
		}
		tails = append(tails, tl)
	}

	var wg sync.WaitGroup
	for _, tl := range tails {
		wg.Add(1)
		go func(tl *tail.Tail) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ln, ok := <-tl.Lines:
					if !ok {
						return
					}
					if ln.Err != nil {
						continue
					}
					select {
					case out <- Line{Source: tl.Filename, Text: ln.Text}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(tl)
	}

	// Dọn dẹp: khi ctx hủy, dừng mọi tailer rồi đóng kênh.
	go func() {
		<-ctx.Done()
		for _, tl := range tails {
			_ = tl.Stop()
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	return out, nil
}
