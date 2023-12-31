# Azure Policy Evaluator

[![ci](https://github.com/JanneMattila/azure-policy-evaluator/actions/workflows/ci.yml/badge.svg)](https://github.com/JanneMattila/azure-policy-evaluator/actions/workflows/ci.yml)

This is personal and very **experimental** project
so don't expect anything from it.

## Background

Azure Policy development is too hard.
Unfortunately, typical policy development flow is:

- You manipulate JSON files
- You deploy them to Azure
- You wait a bit
- You create manually resources for your test scenarios
to see if your policy works as expected

Above is not very efficient and it's time consuming and it does not match modern
development practices that people are used to.

You might not always even realize that testing
just in Azure Portal is not enough.
Azure Portal might use APIs in such a way that your blocking
policy works, but if you then use e.g., Azure CLI or Azure PowerShell,
then your policy might not work as expected.

Example:

Try to deny inbound traffic to port 22 on Network Security Group (NSG).

If you test this policy in Azure Portal by adding inbound rule to allow this traffic,
policy correctly blocks you from doing that. So, it works as expected.

If you then try to do the same with Azure PowerShell:

```PowerShell
$nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resourceGroupName

$nsg | Add-AzNetworkSecurityRuleConfig `
    -Name $ruleName `
    -Description "Allow SSH" `
    -Access Allow `
    -Protocol "*" `
    -Direction "Inbound" `
    -Priority 100 `
    -SourceAddressPrefix "*" `
    -SourcePortRange "*" `
    -DestinationAddressPrefix "*" `
    -DestinationPortRange $port

$nsg |  Set-AzNetworkSecurityGroup
```

Your policy _might_ not block this time and your inbound rule is successfully created.
This is exactly what you don't want to happen.

Above can happen if other one is sending full NSG object:

`Microsoft.Network/networkSecurityGroups`

and other one is sending just the rule:

`Microsoft.Network/networkSecurityGroups/securityRules`

To test these small differences, it would take even more time.

What if we could use tool to do local testing of our policies?
Something that runs very similar to any unit test framework.
You edit the file and voila, you see the results immediately
in your console.

What if we would have example test cases for you to use?
You're developing NSG rules, then here are _set of test cases_
to ease your development.

## Experiment

The idea is to create a tool that can evaluate Azure Policy definitions 
against a given Azure Resource Manager JSON objects. 

Example ARM Resource for Network Security Group (NSG):

```json
{
  "name": "nsg-app",
  "type": "Microsoft.Network/networkSecurityGroups",
  "location": "northeurope",
  "properties": {
    "securityRules": [
      {
        "type": "Microsoft.Network/networkSecurityGroups/securityRules",
        "properties": {
          "protocol": "*",
          "sourcePortRange": "*",
          "destinationPortRange": "22",
          "sourceAddressPrefix": "*",
          "destinationAddressPrefix": "10.0.0.4",
          "access": "Allow",
          "priority": 4096,
          "direction": "Inbound",
          "sourcePortRanges": [],
          "destinationPortRanges": [],
          "sourceAddressPrefixes": [],
          "destinationAddressPrefixes": []
        }
      }
    ]
  }
}
```

Example policy to prevent inbound traffic on defined ports
([deny-ports-nsg](https://github.com/Azure/Community-Policy/tree/main/policyDefinitions/Network/deny-ports-nsg) from Community Policy Repo):

```json
{
  "properties": {
    "mode": "All",
    "policyRule": {
      "if": {
        "anyOf": [
          {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.Network/networkSecurityGroups/securityRules"
              },
              {
                "not": {
                  "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
                  "notEquals": "*"
                }
              },
              {
                "anyOf": [
                  {
                    "field": "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange",
                    "equals": "22"
                  },
                  {
                    "field": "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange",
                    "equals": "3389"
                  }
                ]
              }
            ]
          },
          {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.Network/networkSecurityGroups"
              },
              {
                "count": {
                  "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
                  "where": {
                    "allOf": [
                      {
                        "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix",
                        "equals": "*"
                      },
                      {
                        "anyOf": [
                          {
                            "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].destinationPortRange",
                            "equals": "22"
                          },
                          {
                            "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].destinationPortRange",
                            "equals": "3389"
                          }
                        ]
                      }
                    ]
                  }
                },
                "greater": 0
              }
            ]
          }
        ]
      },
      "then": {
        "effect": "Deny"
      }
    }
  }
}
```

Now we can run our tool to evaluate the policy against the resource:

```console
$ ape -p azurepolicy.json -t nsg.json

10:10:00 info: Program[0] Policy 'azurepolicy' with test 'securityrule-allows-ssh-deny' evaluated to 'Deny' which was expected -> PASS
```

See demo in action:

```powershell
# TO BE ADDED
```

## Limitations

As this is just an **experiment**, there are many limitations (list is not even exhaustive):

- Most of the [template functions](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions) are not implemented
  - `parameters` is implemented
- Most of the [data types](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/data-types) are not implemented
  - `string`, `int` and `bool` are implemented
- Most of the [policy conditions](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#conditions) are not implemented
  - `field`, `count`, `in`, `notIn`, `allOf`, `anyOf`, `not`, `equals`, `notEquals`, `greater`, `greaterOrEquals`, `less`, `lessOrEquals` are implemented _at least partially_
- [Aliases](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#aliases) are not implemented
  - Only `[*]` array alias is implemented
- `"source": "action"` is not implemented ([info](https://github.com/MicrosoftDocs/azure-docs/issues/5899))

## Usage

Download the tool:

1. Go to [Actions](https://github.com/JanneMattila/azure-policy-evaluator/actions/workflows/ci.yml)
2. Select latest successful run
3. Download artifact based on your platform
   - `ape-windows` for Windows
   - `ape-linux` for Linux
4. Extract the artifact
5. Add the executable to location which is in your `PATH` environment variable

Ready to use:

```console
$ ape --help

Description:
  Azure Policy Evaluator allows you to evaluate Azure Policy files against test files.
  You can use this to test your policies before deploying them to Azure.

  The tool can be used in two ways:

  1. Evaluate a single policy file against a single test file.
  2. Watch for policy changes in the folders and evaluate them against all test files in the sub-folders.

  More information can be found here:
  https://github.com/JanneMattila/azure-policy-evaluator

Usage:
  ape [options]

Options:
  -p, --policy <policy>              Policy file to evaluate
  -t, --test <test>                  Test file to use in evaluation
  -w, --watch                        Watch folder for policy changes
  -f, --watch-folder <watch-folder>  Override watch folder path
  --logging <debug|info|trace>       Logging verbosity [default: info]
  --version                          Show version information
  -?, -h, --help                     Show help and usage information
```

Most common usage is to navigate to the policy folder and then execute:

```powershell
ape -w
```

To see `debug` level logging:

```powershell
ape -w --logging debug
```

To evaluate single policy against single test file:

```powershell
ape -p azurepolicy.json -t nsg.json
```

To allow using `ape` from any folder, you can add it to
any folder which is in your `PATH` environment variable.

In case you want to remove `ape` from your system, you can
just delete the executable. If you have fogotten where you
installed it, you can use these commands to find the executable:

Command-prompt:

```cmd
where ape
```

PowerShell:

```powershell
gcm ape | fl
```

## Links

[Azure Policy Samples](https://github.com/Azure/azure-policy/)

[Community Policy Repo](https://github.com/Azure/Community-Policy/)
