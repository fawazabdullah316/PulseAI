# -----------------------------------------------------------------------
# PULSEAI - run_local.ps1
#
# Runs the server directly with Python, no Docker required.
# Uses SQLite (instead of PostgreSQL) and in-memory cache/rate-limiting
# (instead of Redis) automatically - fine for local testing, not for real
# production traffic with multiple instances.
#
# Usage (from PowerShell, inside the pulseai-v4 folder):
#     .\run_local.ps1
#
# If PowerShell blocks the script from running the first time, run this
# once (one-time only, per machine):
#     Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# -----------------------------------------------------------------------

# Load .env directly into this PowerShell process's environment. The app
# also tries to load .env itself via python-dotenv, but doing it here too
# means it works even if that Python-side loading ever has trouble reading
# the file (different parser, no dependency on python-dotenv at all) -
# whichever sets a variable first wins, and both produce the same result
# when the file is read correctly.
if (Test-Path ".env") {
    Write-Host "Loading .env..." -ForegroundColor Cyan
    Get-Content ".env" | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '=' } | ForEach-Object {
        $parts = $_ -split '=', 2
        $key   = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
    }
} else {
    Write-Host "No .env file found in this folder - continuing anyway, but ANTHROPIC_API_KEY etc. need to be set some other way." -ForegroundColor Yellow
}

Write-Host "Installing Python dependencies (first run only, this may take a few minutes)..." -ForegroundColor Cyan
python -m pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "pip install failed - see the error above. Common fix: make sure 'python' is on your PATH (try 'py' instead, or reinstall Python and check 'Add to PATH' during setup)." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting PULSEAI..." -ForegroundColor Cyan
Write-Host "Watch for the line: PULSEAI server ready - that means it's working." -ForegroundColor Yellow
Write-Host "Open http://localhost:8000/docs in your browser once you see it." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C in this window to stop the server." -ForegroundColor Yellow
Write-Host ""

python -m uvicorn server:app --host 0.0.0.0 --port 8000
