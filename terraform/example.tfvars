# Copy to terraform.tfvars (git-ignored) and fill in real values.
# Find your current public IP: (Invoke-RestMethod https://checkip.amazonaws.com).Trim()

my_ips = [
  "203.0.113.10/32", # home
  "198.51.100.20/32" # phone hotspot
]

alert_email = "you@example.com"

# Scenario toggles - keep all false for the baseline
insecure_bucket = false
ssh_open        = false
imds_v1         = false
lambdas_enabled = false
