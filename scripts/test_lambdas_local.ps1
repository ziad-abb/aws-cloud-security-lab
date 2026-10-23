# Phase 3 - test the 3 remediation Lambdas on LocalStack (Docker on, VMs off).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File scripts\test_lambdas_local.ps1
# 1. deploys the stack with ALL three misconfigurations on (bucket public, SSH open, IMDSv1)
# 2. invokes each Lambda with a realistic EventBridge event, checks the fix, invokes again (loop guard)
# 3. destroys everything
$ErrorActionPreference = "Stop"
$ep = "http://localhost:4566"
$reg = "eu-north-1"
$vars = @("-var=ami_id=ami-03cf127a", "-var=cloudtrail_enabled=false",
          "-var=insecure_bucket=true", "-var=ssh_open=true", "-var=imds_v1=true")

function Local { aws --endpoint-url $ep --region $reg @args }

function Invoke-Lambda($name, $eventFile) {
    $out = Join-Path $env:TEMP "$name-out.json"
    Local lambda invoke --function-name $name --payload "fileb://$eventFile" $out | Out-Null
    $r = Get-Content $out -Raw | ConvertFrom-Json
    Write-Host "  -> action: $($r.action)" -ForegroundColor Cyan
    if ($r.errorMessage) { Write-Host "  -> ERROR: $($r.errorMessage)" -ForegroundColor Red }
    return $r
}

function New-Event($template, $map) {
    $txt = Get-Content $template -Raw
    foreach ($k in $map.Keys) { $txt = $txt.Replace($k, $map[$k]) }
    $dst = Join-Path $env:TEMP (Split-Path $template -Leaf)
    Set-Content $dst $txt -Encoding ascii
    return $dst
}

Write-Host "== Deploying stack with all 3 misconfigurations ON (LocalStack) ==" -ForegroundColor Yellow
Push-Location terraform
tflocal apply -auto-approve @vars | Select-Object -Last 3
$bucket = tflocal output -raw data_bucket
$sg     = tflocal output -raw web_sg_id
$iid    = tflocal output -raw web_instance_id
Pop-Location

$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$common = @{ "ACCOUNT_ID" = "000000000000"; "EVENT_TIME" = $now }

# ---------------- L1 ----------------
Write-Host "`n== L1: S3 Block Public Access ==" -ForegroundColor Yellow
Write-Host "  before: $((Local s3api get-public-access-block --bucket $bucket --query PublicAccessBlockConfiguration --output json) -join '')"
$ev = New-Event "lambda\tests\events\l1_event.json" ($common + @{ "BUCKET_NAME" = $bucket })
Invoke-Lambda "seclab-l1-s3-reblock" $ev | Out-Null
Write-Host "  after:  $((Local s3api get-public-access-block --bucket $bucket --query PublicAccessBlockConfiguration --output json) -join '')"
Write-Host "  second invoke (expect loop guard skip):"
Invoke-Lambda "seclab-l1-s3-reblock" $ev | Out-Null

# ---------------- L2 ----------------
Write-Host "`n== L2: internet-open SG ingress ==" -ForegroundColor Yellow
$q = "SecurityGroupRules[?IsEgress==``false``].[IpProtocol,FromPort,CidrIpv4]"
Write-Host "  before: $((Local ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg" --query $q --output text) -join ' | ')"
$ev = New-Event "lambda\tests\events\l2_event.json" ($common + @{ "SG_ID" = $sg })
Invoke-Lambda "seclab-l2-sg-revoke" $ev | Out-Null
Write-Host "  after:  $((Local ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg" --query $q --output text) -join ' | ')"
Write-Host "  second invoke (expect 'nothing open' skip):"
Invoke-Lambda "seclab-l2-sg-revoke" $ev | Out-Null

# ---------------- L3 ----------------
Write-Host "`n== L3: IMDSv2 enforcement ==" -ForegroundColor Yellow
$q = "Reservations[].Instances[].MetadataOptions.HttpTokens"
Write-Host "  before: $(Local ec2 describe-instances --instance-ids $iid --query $q --output text)"
$ev = New-Event "lambda\tests\events\l3_event.json" ($common + @{ "INSTANCE_ID" = $iid })
Invoke-Lambda "seclab-l3-imds-enforce" $ev | Out-Null
Write-Host "  after:  $(Local ec2 describe-instances --instance-ids $iid --query $q --output text)"
Write-Host "  second invoke (expect 'nothing to fix'):"
Invoke-Lambda "seclab-l3-imds-enforce" $ev | Out-Null

Write-Host "`n== Destroying LocalStack stack ==" -ForegroundColor Yellow
Push-Location terraform
tflocal destroy -auto-approve @vars | Select-Object -Last 1
Pop-Location
