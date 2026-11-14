@echo off
rem Windows build of both halves: compile only (tests: monfilter.py test). Installs and starts
rem nothing. UNVERIFIED: no Windows host has run it.
setlocal
call "%~dp0filter\build.cmd" || exit /b 1
call "%~dp0monitor\build.cmd" || exit /b 1
exit /b 0
