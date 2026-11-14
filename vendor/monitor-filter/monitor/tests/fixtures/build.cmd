@echo off
setlocal
set "ROOT=%~dp0..\.."
set "OUT=%ROOT%\build\fixtures"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do (
    if not defined VCVARS if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo Visual Studio C++ tools were not found.
  exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /W4 /O2 /Fo"%OUT%\\" /Fe:"%OUT%\sensor_probe.exe" "%~dp0sensor_probe.c" ws2_32.lib advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /EHsc /std:c++17 /Fo"%OUT%\\" /Fe:"%OUT%\etw_probe.exe" "%~dp0etw_probe.cpp" ws2_32.lib netapi32.lib ole32.lib oleaut32.lib wbemuuid.lib
if errorlevel 1 exit /b 1
echo built: %OUT%\sensor_probe.exe
echo built: %OUT%\etw_probe.exe
exit /b 0
