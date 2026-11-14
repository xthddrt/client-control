@echo off
setlocal
set "PF86=%ProgramFiles(x86)%"
set "PF=%ProgramFiles%"
set "VSWHERE=%PF86%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%PF%\Microsoft Visual Studio\Installer\vswhere.exe"
set "MSBUILD="
if exist "%PF%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%PF%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%PF86%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%PF86%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
    if not defined MSBUILD set "MSBUILD=%%i"
  )
)
if not defined MSBUILD if exist "%PF%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%PF%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD if exist "%PF86%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%PF86%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD (
  echo MSBuild was not found. Install Visual Studio 2022 Build Tools with the C++ workload.
  exit /b 1
)
"%MSBUILD%" "%~dp0ms-monitor.sln" /m /p:Configuration=Release /p:Platform=x64
if errorlevel 1 exit /b 1
where powershell >nul 2>nul
if not errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\write_build_info.ps1" -Root "%~dp0."
  if errorlevel 1 echo [warn] build-info.json was not written
)
for %%a in (%*) do (
  if /I "%%a"=="--with-fixtures" (
    call "%~dp0tests\fixtures\build.cmd"
    if errorlevel 1 exit /b 1
  )
)
exit /b 0
