# Windows PowerShell version of run_all_scoring.sh
# 전체 결과 채점 스크립트

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"

$SCRIPT_DIR = $PSScriptRoot
$ROOT_DIR = [System.IO.Path]::GetFullPath("$SCRIPT_DIR\..\..\..")

# Python 경로 설정
if (Test-Path "$ROOT_DIR\.venv\Scripts\python.exe") {
    $PYTHON = "$ROOT_DIR\.venv\Scripts\python.exe"
} else {
    $PYTHON = "python"
}

Write-Host "=== 전체 결과 채점 ===" -ForegroundColor Cyan
Write-Host ""

$TOTAL = 0
$SUCCESS = 0

# results/*/Lab*/results_raw_*.json 파일들을 검색
$raw_files = Get-ChildItem -Path "$SCRIPT_DIR\results\*\Lab*\results_raw_*.json" -ErrorAction SilentlyContinue

foreach ($file in $raw_files) {
    $dir = $file.DirectoryName
    
    # 이미 채점된 결과가 있는지 확인
    if (Test-Path "$dir\results_analyzed_*.json") {
        $model_lab = "$($file.Directory.Parent.Name)/$($file.Directory.Name)"
        Write-Host "[SKIP] $model_lab — 이미 채점됨" -ForegroundColor Gray
        continue
    }

    $TOTAL++
    $model_lab = "$($file.Directory.Parent.Name)/$($file.Directory.Name)"
    Write-Host "[$TOTAL] 채점: $model_lab" -ForegroundColor Green

    # analyze_results.py 실행
    $process = Start-Process -FilePath $PYTHON -ArgumentList """$SCRIPT_DIR\analyze_results.py""", """$($file.FullName)""" -NoNewWindow -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        $SUCCESS++
    } else {
        Write-Host "  [FAIL] 채점 실패" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "=== 채점 완료: $SUCCESS/$TOTAL ===" -ForegroundColor Cyan
