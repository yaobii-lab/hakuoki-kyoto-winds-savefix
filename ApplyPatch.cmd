@echo off
rem SPDX-License-Identifier: Apache-2.0
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ApplyPatch.ps1"
if errorlevel 1 (echo. & echo Patch failed. See message above.)
pause
