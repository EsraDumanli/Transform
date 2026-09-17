@echo off
REM One-command bootstrap for a fresh clone on Windows: creates a virtualenv,
REM installs dependencies, and sets up a local .env file. A new clone has no
REM database until you run the app for the first time (see .gitignore).
setlocal

cd /d "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 (
  echo python was not found on PATH. Install Python 3.10+ first.
  exit /b 1
)

if not exist .venv (
  echo Creating virtual environment in .venv ...
  python -m venv .venv
)

echo Installing dependencies ...
call .venv\Scripts\activate.bat
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if not exist .env (
  copy .env.example .env >nul
  echo Created .env from .env.example -- edit it now and add your ANTHROPIC_API_KEY
  echo and a random FLASK_SECRET_KEY.
  for /f "delims=" %%s in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET=%%s
  powershell -Command "(Get-Content .env) -replace '^FLASK_SECRET_KEY=.*', 'FLASK_SECRET_KEY=%SECRET%' | Set-Content .env"
) else (
  echo .env already exists -- leaving it as-is.
)

echo.
echo Setup complete. Next steps:
echo   1. Open .env and set ANTHROPIC_API_KEY to your own key.
echo   2. .venv\Scripts\activate.bat
echo   3. python app.py
echo   4. Open http://localhost:5000 and sign up for an account.
echo.
echo Your data (accounts, resumes, postings) lives only in data\job_agent.db
echo on this machine -- it's gitignored and never shared with anyone else's copy.
