@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   InspecThor - Build and Release Script
echo ===================================================

:: Check for CMake
where cmake >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set CMAKE_CMD=cmake
) else (
    set CMAKE_CMD="C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
)

echo [build] Using CMake command: !CMAKE_CMD!

:: Create Release directory structure
echo [build] Setting up Release folder...
if not exist "Release" mkdir "Release"

:: Generate Signatures Database before linking controller resources
echo [build] Executing API signature dictionary parser...
python src/tools/parse_signatures.py
if %ERRORLEVEL% neq 0 (
    echo [error] Signature database generation failed.
    exit /b 1
)

:: Build 64-bit targets
echo [build] Configuring 64-bit build (x64)...
!CMAKE_CMD! -B build64 -S . -A x64
if %ERRORLEVEL% neq 0 (
    echo [error] CMake x64 configuration failed.
    exit /b 1
)

echo [build] Compiling 64-bit Inspecthor targets in Release mode...
!CMAKE_CMD! --build build64 --config Release --target InspecthorController InspecthorAgent InspecthorLoader
if %ERRORLEVEL% neq 0 (
    echo [error] CMake 64-bit compilation failed.
    exit /b 1
)

:: Build 32-bit targets
echo [build] Configuring 32-bit build (x86)...
!CMAKE_CMD! -B build32 -S . -A Win32
if %ERRORLEVEL% neq 0 (
    echo [error] CMake x86 configuration failed.
    exit /b 1
)

echo [build] Compiling 32-bit Inspecthor runtime targets in Release mode...
!CMAKE_CMD! --build build32 --config Release --target InspecthorAgent InspecthorLoader
if %ERRORLEVEL% neq 0 (
    echo [error] CMake 32-bit compilation failed.
    exit /b 1
)

:: Copy Binaries and files to Release folder
echo [build] Copying compiled files to Release folder...
del /q "Release\*.pdb" >nul 2>nul
del /q "Release\*Test*.exe" >nul 2>nul
del /q "Release\InspecthorController32.exe" >nul 2>nul
del /q "Release\InspecthorShellcodeRunner.exe" >nul 2>nul
del /q "Release\InspecthorShellcodeRunner32.exe" >nul 2>nul
del /q "Release\JetBrainsMono-Light.ttf" >nul 2>nul
del /q "Release\signatures.db" >nul 2>nul
del /q "Release\malware_api_profile.json" >nul 2>nul
del /q "Release\imgui.ini" >nul 2>nul
if exist "Release\Test-case" rd /s /q "Release\Test-case"

copy /y "bin\Release\InspecthorController.exe" "Release\"
copy /y "bin\Release\InspecthorAgent.dll" "Release\"
copy /y "bin\Release\InspecthorAgent32.dll" "Release\"
copy /y "bin\Release\InspecthorLoader.exe" "Release\"
copy /y "bin\Release\InspecthorLoader32.exe" "Release\"

echo.
echo ===================================================
echo   InspecThor release build completed successfully!
echo ===================================================
echo.
dir "Release"
exit /b 0
