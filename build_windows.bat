@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo ========================================
echo   NoteNest Windows EXE Build
echo ========================================
echo.

if not exist "memo.py" (
  echo [ERROR] memo.py not found.
  pause
  exit /b 1
)

if not exist "img\NoteNest_icon.ico" (
  echo [ERROR] img\NoteNest_icon.ico not found.
  pause
  exit /b 1
)

python -m pip install -r requirements-dev.txt
if errorlevel 1 (
  echo [ERROR] Package installation failed.
  pause
  exit /b 1
)

rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul

echo [BUILD] Creating dist\NoteNest.exe ...
python -m PyInstaller --noconfirm --clean --onefile --windowed --name NoteNest --icon "img\NoteNest_icon.ico" memo.py
if errorlevel 1 (
  echo [ERROR] PyInstaller build failed.
  pause
  exit /b 1
)

echo.
echo [HASH] Generating SHA-256 checksum ...
rem SHA-256 해시를 함께 배포해 배포 파일의 무결성을 검증할 수 있게 한다.
rem 사용자는 배포판을 다운로드한 뒤 다음 명령으로 확인:
rem   Get-FileHash NoteNest.exe -Algorithm SHA256
certutil -hashfile "dist\NoteNest.exe" SHA256 | findstr /v ":" > "dist\SHA256SUMS.txt"
echo NoteNest.exe >> "dist\SHA256SUMS.txt"
type "dist\SHA256SUMS.txt"

echo.
echo [DONE] %cd%\dist\NoteNest.exe
echo        %cd%\dist\SHA256SUMS.txt
pause
