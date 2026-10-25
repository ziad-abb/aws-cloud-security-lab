# Runbook: Phase 5 hardening + Prowler #3 ("after" score)

One AWS session, about 1 hour. **The VMs are not needed** (Prowler runs on Windows). Cost: a few cents.
All commands are PowerShell from the repo root unless stated otherwise.

## 0. Before the session (offline)
```powershell
cd terraform
terraform init
terraform validate
cd ..
```
`validate` must print **Success!** (the new file `terraform/hardening.tf` adds no provider).

## 1. Deploy the baseline + hardening
```powershell
cd terraform
terraform plan -var="hardening=true" -out tfplan
terraform apply tfplan
cd ..
```
- Expect **60 baseline + 18 hardening resources** (78) to add. All scenario toggles stay `false`; the Lambda rules stay disabled (not needed for this scan).
- No SNS confirmation is needed for this session.
- If the NACL ever breaks the instance's SSM connection, run `terraform apply -var="hardening=true"` after removing the NACL block, or simply skip it: the instance is not needed for the score.

## 2. Manual hardening (outside Terraform)
**2a. Admin permissions through a group (CIS: no policies attached directly to users).** Add the group first, then detach, so you never lose access:
```powershell
aws iam create-group --group-name admins
aws iam attach-group-policy --group-name admins --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam add-user-to-group --group-name admins --user-name admin
Start-Sleep -Seconds 15
aws iam list-groups-for-user --user-name admin --query "Groups[].GroupName" --output text
aws iam detach-user-policy --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
Start-Sleep -Seconds 15
aws iam list-users --query "Users[].UserName" --output text
```
The last command must still work (it proves the group gives the access). If it fails, re-attach the policy to the user: `aws iam attach-user-policy --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`.

**2b. Delete the unused default VPC:**
```powershell
powershell -ExecutionPolicy Bypass -File scripts\delete_default_vpc.ps1
```
It asks for confirmation and refuses if anything still runs in the default VPC.

## 3. Prowler #3
Wait ~5 minutes after the apply, then:
```powershell
$env:PYTHONUTF8="1"
prowler aws -b --compliance cis_7.0_aws --output-directory reports\prowler\3-after
```
Note the CIS 7.0 compliance percentage from the end of the output.

## 4. Sanitized summary (the only Prowler file that gets committed)
```powershell
python scripts\prowler_summary.py reports\prowler\run1-baseline reports\prowler\2-during reports\prowler\3-after | Out-File -Encoding utf8 reports\prowler\summary.md
Select-String -Path reports\prowler\summary.md -Pattern "\d{12}|arn:aws|AKIA"
```
The `Select-String` must print **nothing** (no account ID, ARN or key ID). The summary lists overall scores, failures per CIS section and the requirements that changed between #2 and #3.

## 5. Keep the account-level guardrails, destroy the rest
The account settings below cost nothing and should stay after the lab. Remove them from Terraform state so `destroy` leaves them in place:
```powershell
cd terraform
terraform state rm "aws_s3_account_public_access_block.this[0]" "aws_iam_account_password_policy.this[0]" "aws_ec2_instance_metadata_defaults.this[0]"
terraform destroy -var="hardening=true"
cd ..
```
`destroy` should remove everything else (75 resources). The `admins` group and the deleted default VPC are not managed by Terraform and stay as they are.

> Consequence: with account-level BPA on, scenario S1 can no longer be reproduced unless you remove it (`aws s3control delete-public-access-block --account-id <ACCOUNT_ID>`). That's intended: the scenarios are finished.

## 6. After the session
- Commit `terraform/hardening.tf`, the scripts, `reports/prowler/summary.md` (check `git status`: the raw `3-after/` folder must stay ignored).
- Update `README.md` / `README.fr.md` (CIS "after" score) and the kickoff brief.
- Update the risk register: R01, R04, R05 actions → Done; residual scores if they change.
