@echo off
setlocal
cd /d "%~dp0"

set "GIT_EXE=C:\Program Files\Git\cmd\git.exe"
set "REMOTE_URL=https://github.com/YASH-876/scamsense-ai-nlp.git"

if not exist "%GIT_EXE%" (
  echo Git was not found. Please reinstall Git for Windows, then run this file again.
  pause
  exit /b 1
)

echo Preparing ScamSense AI/NLP files for GitHub...
echo.
echo Git needs an author name and email for the first commit.
if "%GIT_NAME%"=="" set /p "GIT_NAME=Enter your name (example: Yashwardhan Rathod): "
if "%GIT_EMAIL%"=="" set /p "GIT_EMAIL=Enter the email used in your GitHub account: "

if "%GIT_NAME%"=="" (
  echo Name cannot be empty.
  pause
  exit /b 1
)
if "%GIT_EMAIL%"=="" (
  echo Email cannot be empty.
  pause
  exit /b 1
)

"%GIT_EXE%" config --global user.name "%GIT_NAME%"
"%GIT_EXE%" config --global user.email "%GIT_EMAIL%"
"%GIT_EXE%" config user.name "%GIT_NAME%"
"%GIT_EXE%" config user.email "%GIT_EMAIL%"

"%GIT_EXE%" remote get-url origin >nul 2>&1
if errorlevel 1 "%GIT_EXE%" remote add origin "%REMOTE_URL%"

"%GIT_EXE%" add .
"%GIT_EXE%" commit -m "feat: add multilingual AI/NLP scam analyzer"
"%GIT_EXE%" branch -M main

echo.
echo Pushing project to GitHub...
"%GIT_EXE%" push -u origin main

if errorlevel 1 (
  echo.
  echo Push did not finish. If GitHub asks to sign in, complete it in the browser and run this file once more.
) else (
  echo.
  echo SUCCESS: Your project is live at %REMOTE_URL%
)

pause
