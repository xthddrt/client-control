@echo off
setlocal
set "ROOT=%~dp0.."
set "OUT=%ROOT%\build\tests"
set "PYTHON=python"
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
cl /nologo /W4 /WX /O2 /EHsc /std:c++17 /Fo"%OUT%\\" /Fe:"%OUT%\integration_regression.exe" "%~dp0integration_regression.cpp" "%ROOT%\agent\integrations.cpp" "%ROOT%\agent\telemetry.cpp" "%ROOT%\agent\classify.cpp" "%ROOT%\agent\rpc_names.cpp" "%ROOT%\agent\etw.cpp" bcrypt.lib tdh.lib advapi32.lib
if errorlevel 1 exit /b 1
pushd "%ROOT%"
"%OUT%\integration_regression.exe"
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" goto finished

"%PYTHON%" "%ROOT%\tests\redact_session_test.py"
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" goto finished

set "RESULT=0"

:finished
popd
exit /b %RESULT%

