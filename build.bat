@echo off
echo === Building netscan.exe ===
echo.
echo Make sure you have Python 3.10+ installed.
echo.

pip install pyinstaller litellm python-dotenv httpx rich tqdm
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

pyinstaller netscan-py.spec --clean
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo.
echo === Build complete! ===
echo Output: dist\netscan.exe
echo.
echo NOTE: nmap must be installed on the target machine and available in PATH.
echo       Place your .env file next to netscan.exe with your GEMINI_API_KEY.
pause
