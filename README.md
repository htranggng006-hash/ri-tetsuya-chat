# ĐỀ TÀI: XÂY DỰNG ỨNG DỤNG CHAT AN TOÀN SỬ DỤNG MÃ HÓA LAI ELGAMAL–AES, CHỮ KÝ SỐ ELGAMAL VÀ QUẢN LÝ KHÓA

Dự án được xây dựng hoàn chỉnh bằng ngôn ngữ **C# (.NET 10)**, đáp ứng đầy đủ và bám sát toàn bộ cơ sở lý thuyết mật mã:
1. **Mã hóa bất đối xứng ElGamal (Chương 1)**: Dựa trên bài toán Logarit rời rạc (DLP), hỗ trợ nhóm số nguyên tố chuẩn RFC 3526 MODP 2048-bit / 3072-bit và Toy Group (p=23, g=5).
2. **Mã hóa đối xứng AES-256-GCM (Chương 2.1 - 2.2)**: Khóa 256-bit sinh mới cho từng tin nhắn (CSPRNG), Nonce 12 byte, Thẻ xác thực Auth Tag 16 byte, gắn kết dữ liệu xác thực bổ sung AAD.
3. **Mã hóa lai ElGamal–AES (Chương 2.3)**:
   - Chuyển đổi khóa AES sang số nguyên: $u = \text{OS2IP}(K)$, $m = (u + 1)^2$.
   - Kiểm tra thặng dư bậc hai và số chính phương khi giải mã: $u = \lfloor\sqrt{m}\rfloor - 1$, $K = \text{I2OSP}(u, 32)$.
   - Phong bì bảo vệ kép: $W_A$ (cho người gửi xem lại lịch sử) và $W_B$ (cho người nhận giải mã).
4. **Chữ ký số ElGamal kết hợp SHA-256 (Chương 3)**:
   - Tạo giá trị băm $h = \text{SHA-256}(M) \bmod (p - 1)$.
   - Khóa ngẫu nhiên $k$ nguyên tố cùng nhau với $p - 1$.
   - Chữ ký $(r, s)$ với $r = g^k \bmod p$, $s = k^{-1}(h - x \cdot r) \bmod (p - 1)$.
   - Xác minh: $g^h \bmod p \stackrel{?}{=} y^r \cdot r^s \bmod p$.
5. **Quản lý khóa toàn diện (Chương 5)**:
   - Tách biệt cặp khóa Mã hóa ($PK_{enc}, SK_{enc}$) và cặp khóa Ký ($PK_{sig}, SK_{sig}$).
   - Lưu trữ Keystore an toàn: Dẫn xuất khóa từ mật khẩu bằng PBKDF2 (100.000 vòng, salt 32 byte) + mã hóa AES-256-GCM.
   - Dấu vân tay khóa (Key Fingerprint): Băm SHA-256 định dạng `FA:3B:...` dùng đối chiếu out-of-band chống MITM.
   - Sao lưu, khôi phục (Export/Import JSON) và Thay đổi/Thu hồi khóa (Key Rotation).

---

## 📁 CẤU TRÚC THƯ MỤC DỰ ÁN

```text
SecureChatApp/
├── src/
│   ├── SecureChat.Core/             # Thư viện thuần C# xử lý toàn bộ thuật toán mật mã
│   │   ├── Crypto/
│   │   │   ├── BigIntegerMath.cs    # Lũy thừa nhanh, Nghịch đảo Modulo (Euclid mở rộng), Căn bậc hai, OS2IP/I2OSP
│   │   │   ├── StandardGroups.cs    # RFC 3526 MODP 2048-bit, 3072-bit, Toy Group 23
│   │   │   ├── ElGamalEncryption.cs # Sinh khóa, Mã hóa (c1, c2), Giải mã ElGamal
│   │   │   ├── ElGamalSignature.cs  # Tạo và xác minh chữ ký số ElGamal với SHA-256
│   │   │   ├── AesGcmCipher.cs      # AES-256-GCM (Khóa 32B, Nonce 12B, Tag 16B, AAD)
│   │   │   └── HybridEncryptionService.cs # Gói phong bì lai, bọc khóa K, ký và mở phong bì
│   │   ├── KeyManagement/
│   │   │   ├── KeyModels.cs         # Bundle, DTOs, Keystore file models
│   │   │   └── KeyManager.cs        # Sinh khóa, PBKDF2 derivation, Keystore encryption, Fingerprint
│   │   └── Models/
│   │       └── MessageEnvelope.cs   # Cấu trúc phong bì E = (Metadata, WA, WB, N, C, T, σ)
│   │
│   ├── SecureChat.Server/           # ASP.NET Core Web API + SignalR E2EE Relay Hub + Web UI
│   │   ├── Hubs/ChatHub.cs          # Định tuyến tin nhắn E2EE (Server KHÔNG thấy bản rõ hay khóa riêng)
│   │   ├── Services/
│   │   │   ├── PublicKeyDirectory.cs # Danh bạ khóa công khai & dấu vân tay
│   │   │   └── UserAccountStore.cs   # Quản lý tài khoản (Đăng ký/Đăng nhập, PBKDF2 hash, lưu Keystore mã hóa)
│   │   ├── wwwroot/                 # Giao diện Web hiện đại (HTML5, CSS3, JS, SignalR client)
│   │   │   ├── index.html           # Giao diện Chat, Tab Đăng Ký/Đăng Nhập, Quản lý khóa, Thử nghiệm tấn công
│   │   │   ├── style.css            # Dark mode giao diện hiện đại
│   │   │   └── app.js               # Logic điều khiển, Kính lúp mật mã (Crypto Inspector)
│   │   └── Program.cs               # Minimal API & SignalR endpoint config
│   │
│   └── SecureChat.WpfClient/        # Ứng dụng Desktop Windows WPF chuyên nghiệp
│       ├── MainWindow.xaml          # Giao diện WPF chia 3 cột (Danh bạ, Chat E2EE, Live Inspector)
│       └── MainWindow.xaml.cs       # Logic mã hóa nội bộ máy khách WPF
│
├── tests/
│   └── SecureChat.Tests/            # Kiểm thử tự động xUnit bao phủ 100% các ví dụ lý thuyết
│       └── CryptoCoreTests.cs
│
├── run-server.bat                   # File chạy nhanh Web Server và tự mở trình duyệt
├── run-wpf.bat                      # File chạy nhanh WPF Desktop App
└── run-tests.bat                    # File chạy nhanh Unit Tests
```

---

## 🚀 HƯỚNG DẪN CHẠY ỨNG DỤNG

### Cách 1: Chạy Giao Diện Web (Khuyên dùng - Rất nhanh và tiện demo)
1. Mở thư mục dự án và nhấp đúp vào **`run-server.bat`** (hoặc mở Terminal chạy: `dotnet run --project src/SecureChat.Server/SecureChat.Server.csproj`).
2. Trình duyệt sẽ tự động mở trang web: **`http://localhost:5000`**.
3. Để thử nghiệm trò chuyện 2 người:
   - **Tab trình duyệt 1**: Nhập tên **Alice**, mật khẩu `MatKhau@2026`, bấm **"Tạo Mới Bộ Khóa & Vào Chat"**.
   - **Tab trình duyệt 2** (hoặc mở ẩn danh/Edge): Nhập tên **Bob**, mật khẩu `MatKhau@2026`, bấm **"Tạo Mới Bộ Khóa & Vào Chat"**.
4. Cả Alice và Bob sẽ thấy nhau xuất hiện ngay lập tức trong danh bạ trực tuyến. Bấm vào tên đối phương để chat!

### Cách 2: Chạy Ứng Dụng Desktop Windows (WPF)
1. Đảm bảo Server đang chạy (ở cổng 5000).
2. Nhấp đúp vào **`run-wpf.bat`** (hoặc chạy: `dotnet run --project src/SecureChat.WpfClient/SecureChat.WpfClient.csproj`).
3. Ứng dụng Desktop WPF sẽ mở ra với đầy đủ các tính năng: Chat E2EE, Kính lúp mật mã theo thời gian thực, Tấn công giả mạo và Quản lý Keystore.

### Cách 3: Chạy Kiểm Thử Tự Động (Unit Tests)
Nhấp đúp vào **`run-tests.bat`** (hoặc chạy `dotnet test`).
Tất cả 6 bài test sẽ vượt qua (Passed 100%) bao gồm:
- Khớp chính xác ví dụ Chương 1.4: $p=23, g=5, x=6, y=8, m=10, k=3 \implies c=(10,14)$, giải mã ra đúng 10.
- Khớp chính xác ví dụ Chương 3.2.4: $p=23, g=5, x=6, y=8, h=13, k=7 \implies (r,s)=(17,3)$, $21 \equiv 21$.
- Mã hóa lai AES-256-GCM và phát hiện thay đổi Tag/AAD.
- Bọc và mở khóa phiên AES trong nhóm 2048-bit chuẩn RFC 3526.
- Toàn bộ chu trình E2EE và phát hiện các kịch bản tấn công.
- Mã hóa Keystore bằng PBKDF2 và từ chối khi nhập sai mật khẩu.

---

## 🎯 KỊCH BẢN THUYẾT TRÌNH & BẢO VỆ ĐỒ ÁN

Khi bảo vệ trước Hội đồng Giám khảo / Giảng viên, bạn có thể thực hiện tuần tự theo kịch bản mẫu sau:

1. **Giới thiệu tính năng Quản lý khóa (Chương 5)**:
   - Chỉ ra Dấu vân tay khóa (Fingerprint SHA-256) của Alice và Bob.
   - Giải thích vai trò của việc đối chiếu vân tay out-of-band để chống tấn công Man-in-the-Middle (MITM).
   - Thao tác **"Xuất File Keystore (Backup)"** để chứng minh khóa riêng được mã hóa bằng PBKDF2 + AES-GCM trước khi lưu xuống đĩa.
2. **Gửi tin nhắn an toàn (Chương 2 & 3)**:
   - Alice gửi: *"Xin chào Bình, chúc mừng đề tài thành công!"*.
   - Bob nhận được và hiển thị bình thường.
   - Bấm vào nút **"🔬 Kính Lúp Mật Mã"** trên tin nhắn:
     - Cho Giám khảo xem **Khóa phiên AES-256 ngẫu nhiên**.
     - Cho xem bước chuyển đổi: $u = \text{OS2IP}(K)$, $m = (u+1)^2$.
     - Cho xem cặp bản mã ElGamal $W_B = (c_1, c_2)$ và $W_A = (c_1, c_2)$.
     - Cho xem Nonce 12 byte, Ciphertext Base64, Auth Tag 16 byte.
     - Cho xem Chữ ký số ElGamal $(r, s)$ và công thức xác minh $g^h \bmod p \equiv y^r \cdot r^s \bmod p$.
3. **Thực nghiệm Tấn công (Attack Simulation)**:
   - Chuyển sang chế độ **"⚠️ Sửa Ciphertext"** và gửi tin nhắn:
     $\rightarrow$ Phía Bob lập tức báo động đỏ: `🚨 PHÁT HIỆN TẤN CÔNG: Authentication tag mismatch!`.
   - Chuyển sang chế độ **"⚠️ Sửa Chữ ký (r, s)"** và gửi:
     $\rightarrow$ Phía Bob báo động đỏ: `🚨 CHỮ KÝ SỐ KHÔNG HỢP LỆ: Phát hiện phong bì bị giả mạo!`.
4. **Trực quan hóa công thức lý thuyết (Theory Lab Tab)**:
   - Mở tab **"Phòng Lý Thuyết"** trên giao diện Web.
   - Bấm xem bảng từng bước của Ví dụ Chương 1 và Chương 3: Hệ thống in ra từng phép lũy thừa nhanh, nghịch đảo modulo và kết quả khớp 100% với đề cương lý thuyết.
