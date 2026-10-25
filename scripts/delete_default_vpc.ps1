# Phase 5 hardening: delete the unused DEFAULT VPC in the lab region (CIS: its default security group
# allows traffic between members, and nothing should run in it). Deletes, in order: internet gateway,
# subnets, then the VPC. Refuses to run if anything (a network interface) still lives in it.
# Recreate later if ever needed:  aws ec2 create-default-vpc
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File scripts\delete_default_vpc.ps1
$ErrorActionPreference = "Stop"
$region = "eu-north-1"

$vpc = aws ec2 describe-vpcs --region $region --filters Name=is-default,Values=true --query "Vpcs[0].VpcId" --output text
if (-not $vpc -or $vpc -eq "None") { Write-Host "No default VPC in $region. Nothing to do."; exit 0 }

$enis = aws ec2 describe-network-interfaces --region $region --filters "Name=vpc-id,Values=$vpc" --query "NetworkInterfaces[].NetworkInterfaceId" --output text
if ($enis) { throw "Default VPC $vpc still has network interfaces ($enis). Not deleting." }

$answer = Read-Host "Delete default VPC $vpc in $region? Type yes"
if ($answer -ne "yes") { Write-Host "Cancelled."; exit 0 }

foreach ($igw in (aws ec2 describe-internet-gateways --region $region --filters "Name=attachment.vpc-id,Values=$vpc" --query "InternetGateways[].InternetGatewayId" --output text) -split "\s+" | Where-Object { $_ }) {
    aws ec2 detach-internet-gateway --region $region --internet-gateway-id $igw --vpc-id $vpc
    aws ec2 delete-internet-gateway --region $region --internet-gateway-id $igw
    Write-Host "deleted IGW $igw"
}
foreach ($sn in (aws ec2 describe-subnets --region $region --filters "Name=vpc-id,Values=$vpc" --query "Subnets[].SubnetId" --output text) -split "\s+" | Where-Object { $_ }) {
    aws ec2 delete-subnet --region $region --subnet-id $sn
    Write-Host "deleted subnet $sn"
}
aws ec2 delete-vpc --region $region --vpc-id $vpc
Write-Host "Default VPC $vpc deleted."
