# Uploads iam\dev-ci-policy.json to the dev-ci user, filling ACCOUNT_ID at runtime.
# The rendered policy only exists in $env:TEMP and is deleted afterwards (never committed).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File scripts\put_dev_ci_policy.ps1
$ErrorActionPreference = "Stop"

$AccountId = aws sts get-caller-identity --query Account --output text
if (-not $AccountId) { throw "Could not read the account ID (aws sts get-caller-identity)" }

$tmp = Join-Path $env:TEMP "dev-ci-policy.json"
(Get-Content iam\dev-ci-policy.json -Raw) -replace 'ACCOUNT_ID', $AccountId | Out-File $tmp -Encoding ascii
try {
    Get-Content $tmp -Raw | ConvertFrom-Json | Out-Null   # fails here if the JSON is broken
    aws iam put-user-policy --user-name dev-ci --policy-name dev-ci-least-priv --policy-document "file://$tmp"
    if ($LASTEXITCODE -ne 0) { throw "put-user-policy failed" }
    Write-Host "dev-ci-least-priv uploaded (account ID filled at runtime)"
}
finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
