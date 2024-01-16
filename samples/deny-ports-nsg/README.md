# Network Security Group (NSG): Deny Ports

This policy will deny all traffic to a specified port on a Network Security Group (NSG).

Source of the used `azurepolicy.json`: [Deny Ports](https://github.com/Azure/Community-Policy/tree/main/policyDefinitions/Network/deny-ports-nsg).

In short:

Policy will have effect "Deny" in case it finds a Network Security Group (NSG)
with a rule that allows traffic to ports 22 or 3389.
