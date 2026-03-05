# NetConfigQA2.0 Experiment Execution Script (Windows PowerShell)
# 6 Models x 4 Labs = 24 total runs
#
# Usage:
#   powershell .\Experiment\code\NetConfigQA2_2\run_all_experiments.ps1

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"

$SCRIPT_DIR = $PSScriptRoot
$ROOT_DIR = [System.IO.Path]::GetFullPath("$SCRIPT_DIR\..\..\..")
$EVAL_SCRIPT = "$SCRIPT_DIR\run_eval.py"
$RESULT_DIR = "$SCRIPT_DIR\results"

# Check Python Binary
if (Test-Path "$ROOT_DIR\.venv\Scripts\python.exe") {
    $PYTHON = "$ROOT_DIR\.venv\Scripts\python.exe"
} else {
    $PYTHON = "python"
}

# Model List (Ollama tags)
$MODELS = @(
    "gpt-oss:20b",
    "qwen3-coder:30b-a3b-q4_K_M",
    "gemma3:27b-it-q4_K_M",
    "glm-4.7-flash:q4_K_M",
    "qwen3.5:27b"
)

# Lab List
$LABS = @("A", "B", "C", "D")

# Display name mapping
$DISPLAY_NAMES = @{
    "gpt-oss:20b" = "GPT-OSS-20B"
    "qwen3-coder:30b-a3b-q4_K_M" = "Qwen3-Coder"
    "gemma3:27b-it-q4_K_M" = "Gemma-3-27B"
    "glm-4.7-flash:q4_K_M" = "GLM-4.7-Flash"
    "qwen3.5:27b" = "Qwen3.5-27B"
}

# Statistics
$TOTAL = $MODELS.Count * $LABS.Count
$CURRENT = 0
$SKIPPED = 0
$COMPLETED = 0
$FAILED = 0

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NetConfigQA2.0 All Experiments Run (PowerShell)"
Write-Host "  Models: $($MODELS.Count) x Labs: $($LABS.Count) = $TOTAL total"
Write-Host "  Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$START_TIME = [DateTime]::Now

foreach ($MODEL in $MODELS) {
    $DISPLAY = $DISPLAY_NAMES[$MODEL]

    foreach ($LAB in $LABS) {
        $CURRENT++

        # Check if result already exists
        $RESULT_CHECK = Join-Path $RESULT_DIR "$DISPLAY\Lab$LAB"
        if (Test-Path $RESULT_CHECK) {
            $json_files = Get-ChildItem -Path "$RESULT_CHECK\results_raw_*.json" -ErrorAction SilentlyContinue
            if ($json_files) {
                Write-Host "[$CURRENT/$TOTAL] $DISPLAY x Lab-$LAB - Already exists, skipping" -ForegroundColor Gray
                $SKIPPED++
                continue
            }
        }

        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Yellow
        Write-Host "[$CURRENT/$TOTAL] $DISPLAY x Lab-$LAB"
        Write-Host "  Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Host "============================================================" -ForegroundColor Yellow

        # Run eval script
        $process = Start-Process -FilePath $PYTHON -ArgumentList """$EVAL_SCRIPT""", "--model", """$MODEL""", "--lab", """$LAB""" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            $COMPLETED++
            Write-Host "[OK] $DISPLAY x Lab-$LAB Completed" -ForegroundColor Green
        } else {
            $FAILED++
            Write-Host "[FAIL] $DISPLAY x Lab-$LAB Failed (ExitCode: $($process.ExitCode))" -ForegroundColor Red
        }

        # Model switching delay
        Write-Host "  Waiting for model switch (10s)..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
}

$END_TIME = [DateTime]::Now
$DURATION = [Math]::Round(($END_TIME - $START_TIME).TotalMinutes, 1)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  All Experiments Completed"
Write-Host "  Completed: $COMPLETED / Failed: $FAILED / Skipped: $SKIPPED"
Write-Host "  Duration: $DURATION min"
Write-Host "  End: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:"
Write-Host "  1. Scoring: powershell .\Experiment\code\NetConfigQA2_2\run_all_scoring.ps1"
Write-Host "  2. GPT-4o-mini (manual): & $PYTHON $EVAL_SCRIPT --model gpt-4o-mini --lab all --backend openai"
