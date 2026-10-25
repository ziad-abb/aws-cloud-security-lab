# Pre-publish safety check (run from the repo root BEFORE making the repo public or pushing new material).
# Scans the WHOLE Git history (text and Office/zip files) for access-key IDs, the AWS account ID and given
# IP prefixes, checks that no forbidden file is tracked, and runs TruffleHog (Docker) if available.
# The sensitive values are passed as parameters / read at runtime, so they never appear in this file.
#
#   powershell -ExecutionPolicy Bypass -File scripts\prepublish_check.ps1 -IpPrefix "203.0.113.","198.51.100."   # use YOUR home and mobile prefixes
#
param(
    [string[]]$IpPrefix = @(),          # e.g. your home and mobile IP prefixes
    [switch]$SkipTruffleHog
)
$ErrorActionPreference = "Stop"
$fail = 0

$acct = aws sts get-caller-identity --query Account --output text 2>$null
$patterns = @('AKIA[0-9A-Z]{16}', 'ASIA[0-9A-Z]{16}', 'tskey-[A-Za-z0-9-]+')
if ($acct) { $patterns += [regex]::Escape($acct) } else { Write-Host "WARN: could not read the account ID (no AWS credentials); account-ID check skipped" }
foreach ($p in $IpPrefix) { $patterns += [regex]::Escape($p) }
$rx = ($patterns -join '|')

Write-Host "== 1. Text history (git log -p --all)"
$hits = git log -p --all --format="%h" | Select-String -Pattern $rx -AllMatches
if ($hits) { $fail++; $hits | Select-Object -First 10 | ForEach-Object { Write-Host "  HIT: $($_.Line.Trim())" } } else { Write-Host "  clean" }

Write-Host "== 2. Office / zip files in every commit (xlsx, docx, pptx, zip)"
$tmp = Join-Path $env:TEMP "prepub"; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory $tmp | Out-Null
$blobs = git rev-list --all --objects | Where-Object { $_ -match '\.(xlsx|docx|pptx|zip)$' }
$n = 0
foreach ($line in $blobs) {
    $sha, $path = $line -split ' ', 2
    $n++; $zip = Join-Path $tmp "$n.zip"; $dir = Join-Path $tmp "$n"
    cmd /c "git cat-file -p $sha > `"$zip`""
    try { Expand-Archive $zip $dir -Force } catch { Write-Host "  WARN: could not unzip $path"; continue }
    $h = Get-ChildItem $dir -Recurse -File | Select-String -Pattern $rx -List
    if ($h) { $fail++; Write-Host "  HIT in $path (blob $($sha.Substring(0,8)))" }
}
Write-Host "  $n binary version(s) checked"
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "== 3. Forbidden tracked files"
$bad = git ls-files | Select-String -Pattern '(^|/)(tfplan|.*\.tfstate.*|terraform\.tfvars|\.env)$|^evidence/|^data/|^reports/prowler/[^/]+/'
if ($bad) { $fail++; $bad | ForEach-Object { Write-Host "  TRACKED: $_" } } else { Write-Host "  clean" }

if (-not $SkipTruffleHog) {
    Write-Host "== 4. TruffleHog (full history, Docker)"
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        docker run --rm -v "${PWD}:/repo" trufflesecurity/trufflehog:latest git file:///repo --results=verified,unknown --fail
        if ($LASTEXITCODE -ne 0) { $fail++; Write-Host "  TruffleHog reported findings (or Docker failed)" } else { Write-Host "  clean" }
    } else { Write-Host "  Docker not found: run TruffleHog manually" }
}

Write-Host ""
if ($fail) { Write-Host "RESULT: $fail check(s) FAILED - do not publish"; exit 1 } else { Write-Host "RESULT: all checks passed - safe to publish" }
