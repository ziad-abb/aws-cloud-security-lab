# Offline test (no change in AWS): renders the IAM policies to $env:TEMP with the real account ID,
# checks they are valid JSON and that no placeholder is left, then deletes the rendered copies.
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File scripts\check_policies.ps1
$ErrorActionPreference = "Stop"
$AccountId = aws sts get-caller-identity --query Account --output text
foreach ($f in "iam\dev-ci-policy.json", "iam\wazuh-reader-policy.json") {
    $tmp = Join-Path $env:TEMP ("check-" + (Split-Path $f -Leaf))
    (Get-Content $f -Raw) -replace 'ACCOUNT_ID', $AccountId -replace 'HOME_IP_CIDR', '203.0.113.10/32' | Out-File $tmp -Encoding ascii
    $json = Get-Content $tmp -Raw
    $null = $json | ConvertFrom-Json
    $left = ([regex]::Matches($json, 'ACCOUNT_ID|HOME_IP_CIDR')).Count
    $hasReal = $json.Contains("seclab-") -and $json.Contains($AccountId)
    Write-Host ("{0}: valid JSON, placeholders left = {1}, real names rendered = {2}" -f $f, $left, $hasReal)
    Remove-Item $tmp
}
