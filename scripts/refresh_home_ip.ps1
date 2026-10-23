# Run from the repo root when the home IP changes (dynamic ISP IP).
# 1) re-pins the wazuh-reader IAM policy to the new IP
# 2) replaces the "home" line in Wazuh's seclab-known-ips list on VM1 and restarts the manager
# 3) reminds you to update terraform.tfvars (my_ips)
param([string]$Vm = "ziad@192.168.222.131")

$ip = (Invoke-RestMethod https://checkip.amazonaws.com).Trim()
$cidr = "$ip/32"
Write-Host "Current home IP: $cidr"

$tmp = Join-Path $env:TEMP "wr.json"
(Get-Content iam\wazuh-reader-policy.json -Raw) -replace 'HOME_IP_CIDR', $cidr | Out-File $tmp -Encoding ascii
aws iam put-user-policy --user-name wazuh-reader --policy-name wazuh-reader-least-priv --policy-document "file://$tmp"
if ($LASTEXITCODE -ne 0) { Remove-Item $tmp; throw "put-user-policy failed" }
Remove-Item $tmp
Write-Host "wazuh-reader policy pinned to $cidr"

ssh -t $Vm "sudo sed -i '/:home$/d' /var/ossec/etc/lists/seclab-known-ips && echo '${ip}:home' | sudo tee -a /var/ossec/etc/lists/seclab-known-ips >/dev/null && sudo systemctl restart wazuh-manager && echo 'seclab-known-ips updated, manager restarted'"

Write-Host ""
Write-Host "Now update terraform\terraform.tfvars -> my_ips = [""$cidr"", ...]"
