@echo off
chcp 65001 > nul
echo ========================================================
echo   KHỞI ĐỘNG SERVER CHAT BẢO MẬT ELGAMAL - AES
echo ========================================================
echo Đang chạy ứng dụng Web Server tại:
echo   - http://localhost:7080
echo   - http://localhost:5000
echo Mở trình duyệt và chat mã hóa E2EE không bao giờ lo mất kết nối!
start http://localhost:7080
dotnet run --project src/SecureChat.Server/SecureChat.Server.csproj --urls "http://localhost:7080;http://localhost:5000"
pause
