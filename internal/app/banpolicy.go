package app

import "time"

// banDurationFor trả về thời gian ban cho một lần phạm, theo chính sách leo thang.
// offenseIdx là SỐ LẦN ĐÃ BỊ BAN trước đó (0 = lần đầu). escalation rỗng → ban phẳng
// (luôn dùng flat). Tái phạm vượt độ dài danh sách → dùng mức cuối (vd "permanent").
func banDurationFor(offenseIdx int, escalation []time.Duration, flat time.Duration) time.Duration {
	if len(escalation) == 0 {
		return flat
	}
	if offenseIdx < 0 {
		offenseIdx = 0
	}
	if offenseIdx >= len(escalation) {
		offenseIdx = len(escalation) - 1
	}
	return escalation[offenseIdx]
}
