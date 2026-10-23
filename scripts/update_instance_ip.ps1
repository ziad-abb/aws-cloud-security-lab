# Run from the repo root after every `terraform apply`.
# Writes the lab EC2's public IP into the Wazuh CDB list used by rule 100130 (S4:
# lab-web-role credentials used outside the instance), then restarts the manager.
param([string]$Vm = "ziad@192.168.222.131")

$ip = terraform -chdir=terraform output -raw web_public_ip
if (-not $ip) { throw "No web_public_ip output. Is the stack applied?" }
Write-Host "Lab EC2 public IP: $ip"

# -t: sudo asks for the VM1 password
ssh -t $Vm "echo '${ip}:seclab-web' | sudo tee /var/ossec/etc/lists/seclab-instance-ips >/dev/null && sudo systemctl restart wazuh-manager && echo 'seclab-instance-ips updated, manager restarted'"
