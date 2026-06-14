# Bộ bài launch — edge-guardian (bản tiếng Việt)

Bản tiếng Việt của `SHOW-HN.md`, để đăng ở các cộng đồng dev/sysadmin Việt (group
Facebook, diễn đàn, Viblo/Spiderum…) hoặc làm bản tham chiếu. Tinh thần vẫn giống HN:
**thành thật, kỹ thuật, không nói quá, nêu rõ cả hạn chế.** Nhớ **public repo trước** để
lệnh cài và link hoạt động.

---

## Tiêu đề

Chọn một, giữ factual — không "đỉnh nhất", không "cách mạng":

> edge-guardian – chống xâm nhập cho Linux gói trong một binary, kèm dashboard

Phương án khác:

> edge-guardian – chặn scanner & brute-force SSH ngay tại nftables, có sẵn dashboard miễn phí

> Mình viết edge-guardian: "fail2ban một-file" bằng Go, native nftables, có UI

## Link đăng

Đăng kèm **repo** (cộng đồng kỹ thuật thích xem code): `https://github.com/sondt/edge-guardian`
Rồi post phần nội dung bên dưới làm comment/đoạn mô tả đầu tiên.

---

## Nội dung

Chào mọi người — mình viết edge-guardian vì bảo vệ vài con server Linux đến giờ vẫn là chọn
giữa *rườm rà* và *nặng nề*.

fail2ban lâu đời và ổn, nhưng chỉ nhìn được một host, dựa nhiều vào regex, và không có
giao diện. CrowdSec thì mạnh thật, nhưng phải dựng cả agent + Local API + bouncer +
collections — và cái console đẹp là phần trả phí. Mình muốn con đường ngắn nhất từ "server
đang bị quét" tới "mấy IP đó bị chặn và mình nhận được thông báo", với một dashboard có
sẵn trong bản miễn phí.

Nên edge-guardian là **một binary Go tĩnh** (không cgo, ~8 MB, cross-compile từ Mac sang Linux
nào cũng được). Không database, không agent, không service ngoài — state chỉ là một file
JSON. Nó tail log, ra quyết định, rồi chặn ngay ở tầng kernel bằng một **nftables set có
timeout** (ban tự hết hạn, khỏi cần cron). Khởi động lại máy thì nó nạp lại firewall từ
state.

Hiện phát hiện được (tất cả qua **một pipeline**):

- **HTTP scanner** — mấy request `/.env`, `/wp-login.php`, `/.git` mà một stack không-PHP
  không bao giờ phục vụ. Chặn ngay lần đầu.
- **SSH brute-force** từ auth.log/journald (đã làm cứng chống chiêu log-injection qua
  username kinh điển — nó lấy cụm `from <ip>` *cuối cùng* mà sshd ghi, nên username độc
  hại không thể đổ vạ cho IP vô tội).
- **Port scan**, đếm số **port đích khác nhau** mỗi nguồn (gõ một port nhiều lần không
  phải scan; quét nhiều port mới là scan).
- **Honeypot port** — chạm vào port mồi là bị chặn ngay lập tức.

Thêm: **ban leo thang** cho kẻ tái phạm (1 ngày → 1 tuần → 1 tháng → vĩnh viễn), thông
báo **Telegram + email**, **import blocklist công khai** (FireHOL/Spamhaus) vào nftables
interval set, và **GeoIP offline** chạy được với cả bộ dữ liệu **sapics miễn phí** chứ
không chỉ MaxMind (mình đọc thẳng file mmdb để vượt qua cái guard "database type" của
geoip2).

Phần mình thích nhất là **dashboard** — nhúng thẳng trong binary (Chi + templ + HTMX,
serve ở localhost, bcrypt + CSRF + CSP nghiêm), với điểm nhấn là **"Sentinel line"**: một
đường nhịp sống của mức phơi nhiễm server, phẳng lặng cho tới khi có gì đó vọt lên. Calm
until something happens.

Hai lựa chọn an toàn có chủ đích, vì một daemon tự ban mà khóa luôn chính mình thì vô
dụng: **allowlist CIDR** kiểm trước mọi lần ban, và **chế độ dry-run** — phát hiện, ghi
log, thông báo nhưng KHÔNG đụng firewall — để bạn chạy thử trên production vài ngày, tin
rồi mới bật chặn thật.

Cài một dòng (`curl … | sudo bash`), hoặc `.deb`/`.rpm` (amd64 + arm64), hoặc Docker
image. Khởi động ở dry-run. Giấy phép Apache-2.0.

Trạng thái & hạn chế (nói thẳng):

- Còn sớm (v0.1.0). Lõi miễn phí single-node thì chắc và đã test — mình đã validate phần
  enforce nftables thật, detection và các gói cài trên Linux thật trong CI — nhưng vẫn
  còn non.
- Định hướng là open-core: engine self-hosted vẫn miễn phí; phần trả phí sau này là quản
  lý tập trung nhiều node. Chưa có crowd-sourced blocklist (vấn đề cold-start là thật), nên
  hiện dựa vào blocklist công khai + phát hiện của chính bạn.
- HTTP detector phải chạy ở nơi log ghi IP thật của client (node biên/LB của bạn).
- Port-scan và honeypot cần bạn route dòng `log` của nftables ra một file (journald hoặc
  rsyslog) để nó đọc — có hướng dẫn, nhưng vẫn là một bước.
- Chỉ Linux + nftables. Không iptables, không Windows.
- Cái tên: "edge-guardian" là tiền tố sót lại từ một dự án nội bộ. Mình biết nó không hay cho
  một tool độc lập — rất mong góp ý đổi tên.

Mình muốn nghe góp ý về bộ pattern phát hiện mặc định (rủi ro false-positive), cách tiếp
cận nftables, và liệu "dashboard trong bản miễn phí" có thực sự thay đổi lựa chọn của bạn
so với fail2ban/CrowdSec không. Repo: https://github.com/sondt/edge-guardian

---

## Sẵn câu trả lời (mấy câu hay bị hỏi)

**"Khác fail2ban chỗ nào?"**
> Chủ yếu: một binary thay vì cài Python + cấu hình jail/filter, có dashboard, và dùng
> nftables set native (một rule, IP là dữ liệu) thay vì rule theo từng IP. fail2ban trưởng
> thành và linh hoạt hơn với nguồn log bất kỳ; edge-guardian đánh đổi bớt linh hoạt để lấy cài
> đặt ngắn hơn nhiều và có UI. Nếu fail2ban đang chạy tốt cho bạn thì có lẽ bạn không cần
> cái này.

**"Khác CrowdSec chỗ nào?"**
> CrowdSec mạnh hơn và có crowd-sourced blocklist — đó là lợi thế thật sự của họ. edge-guardian
> không cố thắng cái đó, mà đặt cược vào việc *cực kỳ dễ vận hành* và *cho dashboard miễn
> phí*. Không agent/LAPI/bouncer/collections phải học; chỉ một process.

**"Sao chỉ nftables, không iptables?"**
> nftables set có timeout đúng là primitive phù hợp nhất: một rule, IP nằm trong set, tự
> hết hạn, lookup nhanh kể cả khi nhiều. iptables thì phải quản lý hàng nghìn rule hoặc kéo
> theo ipset. nftables giờ là mặc định trên mọi distro hiện hành. Mình thà làm tốt một thứ
> còn hơn duy trì hai backend.

**"Dashboard expose ra ngoài có an toàn không?"**
> Mặc định bind 127.0.0.1, dùng qua SSH tunnel hoặc reverse proxy TLS. Auth là bcrypt +
> session cookie ký HMAC, mọi thao tác ghi có CSRF, CSP nghiêm, không có inline script.
> Không bao giờ mặc định nghe 0.0.0.0.

**"`curl | sudo bash` thật à?"**
> Hiểu mà. Script ngắn và dễ đọc, và có sẵn `.deb`/`.rpm` + Docker nếu bạn không thích pipe
> vào shell. Installer cũng khởi động ở dry-run — nên việc đầu tiên nó làm là *không* đụng
> tới firewall của bạn.

**"Lấy gì đảm bảo nó không ban nhầm / khóa mình ra ngoài?"**
> Allowlist CIDR kiểm trước mọi lần ban (cho IP văn phòng/VPN/monitoring vào đó), và dry-run
> để quan sát trước khi bật. Ban cũng tự hết hạn qua nftables timeout, và `edge-guardian unban
> <ip>` gỡ sạch một IP. Pattern mặc định nhắm vào path/hành vi mà client bình thường không
> bao giờ chạm, nên false-positive gần như bằng 0 — nhưng vẫn nên chạy dry-run trước.

**"Binary nặng bao nhiêu / phụ thuộc gì?"**
> ~8 MB tĩnh, không cgo. Dependency tối thiểu, liệt kê trong go.mod (nftables qua netlink,
> thư viện tail, TOML, maxminddb, chi/templ cho UI). Phần lớn là stdlib.

**"Có telemetry không?"**
> Không. Nó không gọi ra ngoài trừ những thứ bạn cấu hình (Telegram/email, và URL blocklist
> bạn trỏ tới).
