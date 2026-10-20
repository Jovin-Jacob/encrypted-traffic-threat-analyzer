@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  for %%V in (3.13 3.12 3.11 3.10) do (
    py -%%V -m venv .venv >nul 2>&1
    if not errorlevel 1 goto venv_ready
  )
  where python >nul 2>&1
  if not errorlevel 1 (
    python -m venv .venv
    if not errorlevel 1 goto venv_ready
  )
  goto failed
)
:venv_ready
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m streamlit run app.py --server.address 127.0.0.1
goto end
:failed
echo Setup or launch failed. Install Python 3.10+ and check your internet connection for the initial package install.
pause
:end
endlocal
