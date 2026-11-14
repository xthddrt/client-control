@echo off
setlocal
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
  echo MSBuild was not found at %MSBUILD%.
  exit /b 1
)
%MSBUILD% "%~dp0kfilter.sln" /m /p:Configuration=Release /p:Platform=x64 || exit /b 1
copy /y "%~dp0policy\default-policy.txt" "%~dp0build\Release\tool\default-policy.txt" >nul
copy /y "%~dp0policy\contain-policy.txt" "%~dp0build\Release\tool\contain-policy.txt" >nul
copy /y "%~dp0policy\device-policy-snippet.txt" "%~dp0build\Release\tool\device-policy-snippet.txt" >nul
echo.
echo Outputs:
echo   build\Release\driver\kfilter.sys
echo   build\Release\driver\kfilter.inf
echo   build\Release\tool\kfilterctl.exe
echo   build\Release\tool\default-policy.txt
echo   build\Release\tool\contain-policy.txt
echo   build\Release\tests\kfilter-probe.exe
echo   build\Release\tests\kfilter-idprobe.exe
