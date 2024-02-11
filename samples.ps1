# Show help
ape -h

# Run a single policy test
ape `
  -p samples/Network/deny-ports-nsg/azurepolicy.json `
  -t samples/Network/deny-ports-nsg/tests/securityrule-allows-ssh-deny.json

# Run a single policy test with debug logging
ape `
  -p samples/Compute/audit-vm-byol-compliance/azurepolicy.json `
  -t samples/Compute/audit-vm-byol-compliance/tests/linux-vm-none.json `
  --logging debug

# Run all tests in the samples directory
ape -r samples

# Start watching the samples directory
ape -w -f samples
