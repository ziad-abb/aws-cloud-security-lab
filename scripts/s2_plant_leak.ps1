# S2 - plant the leaked dev-ci key in a fake CI repo (run ONLY at the start of the S2 run).
# Creates a NEW access key for dev-ci, commits it in .env, then "removes" it in a second commit
# (classic history leak), and packs the repo into a git bundle for Kali.
# The secret is never printed: it only exists in the repo history and the bundle.
# Run from the lab repo root:  powershell -ExecutionPolicy Bypass -File scripts\s2_plant_leak.ps1
param([string]$Dir = "$HOME\Documents\aws project\s2-leak")

$ErrorActionPreference = "Stop"
$AccountId = aws sts get-caller-identity --query Account --output text   # never hard-coded in the repo

# Guard: dev-ci must have no key yet (one leak per run).
$existing = aws iam list-access-keys --user-name dev-ci --query "AccessKeyMetadata[].AccessKeyId" --output text
if ($existing) { throw "dev-ci already has key(s): $existing. Delete them before planting a new leak." }

if (Test-Path $Dir) { throw "$Dir already exists. Remove it first (old run)." }
$repo = Join-Path $Dir "acme-ci-pipeline"
New-Item -ItemType Directory -Force $repo | Out-Null
Push-Location $repo
try {
    git init -q -b main
    git config user.name  "ci-dev"
    git config user.email "ci-dev@acme.example"

    Set-Content README.md "# acme-ci-pipeline`nBuild and deploy scripts for the Acme web app."
    Set-Content deploy.sh "#!/bin/sh`n# sync build artifacts`naws s3 ls s3://seclab-data-$AccountId/"
    git add README.md deploy.sh
    git commit -q -m "initial pipeline scripts"

    # Create the key and write it straight into .env (never displayed).
    $k = aws iam create-access-key --user-name dev-ci --output json | ConvertFrom-Json
    $keyId = $k.AccessKey.AccessKeyId
    $created = $k.AccessKey.CreateDate
    Set-Content .env ("AWS_ACCESS_KEY_ID=" + $k.AccessKey.AccessKeyId + "`nAWS_SECRET_ACCESS_KEY=" + $k.AccessKey.SecretAccessKey + "`nAWS_DEFAULT_REGION=eu-north-1")
    Remove-Variable k
    git add .env
    git commit -q -m "add ci config"

    # The "fix" that doesn't fix anything: the key stays in history.
    git rm -q --cached .env
    Remove-Item .env
    Set-Content .gitignore ".env"
    git add .gitignore
    git commit -q -m "remove secrets, add gitignore"

    git bundle create (Join-Path $Dir "acme-ci.bundle") --all 2>$null
}
finally { Pop-Location }

Write-Host "Leak planted. Key ID: $keyId  (created $created UTC) -> write it in the run log."
Write-Host "Bundle: $Dir\acme-ci.bundle  -> copy it to Kali."
