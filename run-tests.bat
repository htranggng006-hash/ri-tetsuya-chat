@echo off
chcp 65001 > nul
echo ========================================================
echo   CHẠY TOÀN BỘ KIỂM THỬ TỰ ĐỘNG (UNIT TESTS)
echo ========================================================
dotnet test SecureChatApp.sln
pause
