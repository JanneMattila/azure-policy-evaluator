# Azure Policy Evaluator

This is personal and very **experimental** project
so don't expect anything from it.

## Background

Azure Policy development is too hard.
Common development flow is:

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
policy does block you from doing that.

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

It might work just fine and your policy does not block you from doing that.

Above can happen if other one is sending full NSG object:

`Microsoft.Network/networkSecurityGroups`

and other one is sending just the rule:

`Microsoft.Network/networkSecurityGroups/securityRules`

To test these small differences, it would take even more time.

What if we could use tool to do local testing of our policies?
Something that runs very similar to any unit test framework.
You edit the file and voila, you see the results immediately
in your console.

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

## Links

[Azure Policy Samples](https://github.com/Azure/azure-policy/)

[Community Policy Repo](https://github.com/Azure/Community-Policy/)
