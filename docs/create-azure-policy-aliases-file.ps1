# https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#aliases
$providers = Get-AzPolicyAlias -ListAvailable

$providers | Select-Object -First 50 | Format-Table -AutoSize
$providers.Count

$providers | Where-Object { $_.Namespace -eq "Microsoft.Compute" }

$compute = $providers `
| Where-Object { $_.Namespace -eq "Microsoft.Compute" -and $_.ResourceType -eq "virtualMachines" }
$compute
$compute.Aliases[5].Name
$compute.Aliases[5].Paths.Path

$vms = $providers `
| Where-Object { $_.Namespace -eq "Microsoft.Compute" -and $_.ResourceType -eq "virtualMachines" } `
| Select-Object -ExpandProperty Aliases `
| Select-Object -First 10

# Option 1:
$policyAliases = @{}
foreach ($provider in $providers) {
    foreach ($alias in $provider.Aliases) {

        if ($null -eq $alias.Paths.Path) {
            continue
        }

        if (!$policyAliases.ContainsKey($provider.Namespace)) {
            $policyAliases[$provider.Namespace] = @{}
        }

        if (!$policyAliases[$provider.Namespace].ContainsKey($provider.ResourceType)) {
            $policyAliases[$provider.Namespace][$provider.ResourceType] = @{}
            $policyAliases[$provider.Namespace][$provider.ResourceType][$alias.Name] = New-Object System.Collections.ArrayList
        }

        if (!$policyAliases[$provider.Namespace][$provider.ResourceType].ContainsKey($alias.Name)) {
            $policyAliases[$provider.Namespace][$provider.ResourceType][$alias.Name] = New-Object System.Collections.ArrayList
        }

        $policyAliases[$provider.Namespace][$provider.ResourceType][$alias.Name].Add($alias.Paths.Path) | Out-Null
    }
}

$policyAliases | ConvertTo-Json -Depth 10 | Out-File -FilePath .\policy-aliases.json

# Option 2:
$policyAliases = @{}
foreach ($provider in $providers) {
    foreach ($alias in $provider.Aliases) {
        if (!$policyAliases.ContainsKey($alias.Name)) {
            # $policyAliases[$alias.Name] = New-Object System.Collections.ArrayList
            $policyAliases[$alias.Name] = @()
        }

        # $policyAliases[$alias.Name].Add($alias.DefaultPath) | Out-Null
        # $policyAliases[$alias.Name] += $alias.DefaultPath
        $policyAliases[$alias.Name] = $alias.DefaultPath
    }
}

$policyAliases | ConvertTo-Json -Depth 10 | Out-File -FilePath .\policy-aliases.json
