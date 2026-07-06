@echo off
rem ---------------------------------------------------------------------------
rem Build the CRYPTO_THREAD_run_once fast-path race test on Windows ARM64.
rem
rem Prerequisite: open the "ARM64 Native Tools Command Prompt for VS"
rem (or run:  vcvarsarm64.bat)
rem so that cl.exe targets ARM64.
rem
rem /O2          : optimize (we WANT aggressive codegen)
rem ---------------------------------------------------------------------------
setlocal

where cl >nul 2>nul
if errorlevel 1 (
    echo [!] cl.exe not found. Open the "ARM64 Native Tools Command Prompt for VS" first.
    exit /b 1
)

cl /nologo /O2 /std:c11 %* CRYPTO_THREAD_run_once_fastpath_race.c /Fe:CRYPTO_THREAD_run_once_fastpath_race.exe
if errorlevel 1 exit /b 1

echo.
echo Build OK. Run:
echo   CRYPTO_THREAD_run_once_fastpath_race.exe                 ^(reproduce: expect VIOLATIONS ^> 0^)
echo   CRYPTO_THREAD_run_once_fastpath_race.exe --fix           ^(reader acquire added: expect 0^)
echo.
