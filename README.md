# XyzArch Compressor

XyzArch là một công cụ nén file mạnh mẽ với khả năng mã hóa tích hợp. Phần mềm cung cấp giao diện người dùng thân thiện để nén, mã hóa và quản lý file với nhiều phương thức mã hóa và tùy chọn xác minh hash.

## Tính Năng

### Nén File
- Nén file hiệu quả sử dụng thuật toán ZIP deflate
- Hỗ trợ chọn nhiều file cùng lúc
- Tùy chọn vị trí lưu file
- Tùy chọn xóa file gốc sau khi nén

### Bảo Mật
- Nhiều phương thức mã hóa:
  - AES-256 (Tiêu chuẩn)
  - 3DES (Quân sự Mỹ)
  - Blowfish (Phương thức thay thế)
  - Mã hóa Chaos tùy chỉnh
- Đo độ mạnh mật khẩu
- Tạo mật khẩu mạnh tự động
- Tạo mã hash tùy chọn (SHA1, MD5, CRC32)

### Giao Diện
- Giao diện hiện đại với theme tối
- Theo dõi tiến trình thời gian thực
- Hệ thống quản lý file
- Hiển thị đồng hồ thời gian thực (UTC+7)
- Điều khiển trực quan

## Cài Đặt

### Yêu Cầu Hệ Thống
```bash
python -m pip install customtkinter
python -m pip install pycryptodome
python -m pip install pytz
```

### Các Bước Cài Đặt
1. Clone repository:
```bash
git clone https://github.com/yourusername/xyzarch.git
```

2. Di chuyển vào thư mục dự án:
```bash
cd xyzarch
```

3. Chạy ứng dụng:
```bash
python xyzarch.py
```

## Hướng Dẫn Sử Dụng

### Nén File
1. Nhấn "Add Files" để chọn file cần nén
2. Chọn phương thức mã hóa (tùy chọn)
3. Chọn tùy chọn tạo mã hash (tùy chọn)
4. Bật/tắt mã hóa và xóa file gốc
5. Nhấn "Compress" và chọn thư mục đích
6. Nhập mật khẩu nếu bật mã hóa

### Giải Nén File
1. Nhấn "Extract" và chọn file .xyzarch
2. Cho biết file có được mã hóa không
3. Nhập mật khẩu nếu cần
4. Chọn vị trí giải nén
5. Đợi hoàn thành

## Tính Năng Bảo Mật

### Phương Thức Mã Hóa
- **AES-256**: Mã hóa tiêu chuẩn công nghiệp
- **3DES**: Mã hóa Triple DES (sử dụng trong quân sự)
- **Blowfish**: Thuật toán mã hóa thay thế
- **Chaos**: Triển khai mã hóa dựa trên lý thuyết hỗn độn

### Bảo Mật Mật Khẩu
- Đo độ mạnh với chỉ số trực quan
- Tạo mật khẩu mạnh tự động
- Tùy chọn hiển thị/ẩn mật khẩu
- Lưu trữ mật khẩu an toàn

## Chi Tiết Kỹ Thuật

### Định Dạng File
- Phần mở rộng .xyzarch tùy chỉnh
- Nén dựa trên ZIP
- Lớp mã hóa tùy chọn
- Hỗ trợ xác minh hash

### Tùy Chọn Hash
- SHA1: Secure Hash Algorithm 1
- MD5: Message Digest Algorithm
- CRC32: Cyclic Redundancy Check

## Đóng Góp
Mọi đóng góp đều được hoan nghênh! Vui lòng gửi Pull Request để đóng góp.

## Giấy Phép
Dự án này được cấp phép theo giấy phép MIT - xem file LICENSE để biết thêm chi tiết.

## Nhà Phát Triển
Phát triển bởi Namtran5905

## Lời Cảm Ơn
- CustomTkinter cho các thành phần giao diện hiện đại
- PyCryptodome cho các thuật toán mã hóa
- Cộng đồng Python cho các thư viện được sử dụng

## Hỗ Trợ
Để được hỗ trợ, vui lòng tạo issue trong repository GitHub hoặc liên hệ với nhà phát triển.

## Lịch Sử Cập Nhật
### Phiên Bản 1.0.0
- Phát hành lần đầu
- Tính năng nén và mã hóa cơ bản
- Triển khai giao diện người dùng
- Nhiều phương thức mã hóa
- Hỗ trợ tạo hash
