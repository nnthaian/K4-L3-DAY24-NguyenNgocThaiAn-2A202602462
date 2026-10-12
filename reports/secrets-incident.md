# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1, chạy với `.gitleaks.toml` và chế độ `--redact --verbose`.
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- File, rule và kết quả quét lịch sử: Gitleaks phát hiện `lab-fake-secret.txt`, dòng 1, rule `lab24-synthetic-token`; kết quả là 1 finding trong 7 commits được quét. Đây là token synthetic, vô hiệu và được cung cấp sẵn cho bài lab, không phải credential thật.
- Kết quả quét file hiện tại: `gitleaks dir --config .gitleaks.toml --redact --verbose .` trả về `INF no leaks found`.
- Nếu đây là credential thật, cần thu hồi (revoke) hoặc rotate ngay, đồng thời xác định phạm vi ảnh hưởng và kiểm tra các nơi credential đã được sử dụng.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ: xoá file khỏi commit hiện tại không xoá secret khỏi Git history và không làm credential đã lộ mất hiệu lực. Pin dependency và hook Gitleaks giúp ngăn lỗi mới, nhưng không thay thế việc revoke/rotate credential đã bị lộ.
