@echo off
chcp 65001 > nul
echo ========================================================
echo   KHỞI ĐỘNG ỨNG DỤNG DESKTOP WPF CLIENT
echo ========================================================
echo Lưu ý: Hãy đảm bảo run-server.bat đang chạy trước!
dotnet run --project src/SecureChat.WpfClient/SecureChat.WpfClient.csproj
pause
