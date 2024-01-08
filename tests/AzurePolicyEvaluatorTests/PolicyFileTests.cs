using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class PolicyFileTests
{
    [Fact]
    public void NetworkSecurityGroupFieldValidationTest()
    {
        // Arrange
        var fieldDocument = JsonDocument.Parse(@"{
            ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange"",
            ""equals"": ""22""
        }");
        var test = JsonDocument.Parse(@"{
            ""type"": ""Microsoft.Network/networkSecurityGroups/securityRules"",
            ""properties"": {
                ""protocol"": ""*"",
                ""sourcePortRange"": ""*"",
                ""destinationPortRange"": ""22"",
                ""sourceAddressPrefix"": ""*"",
                ""destinationAddressPrefix"": ""10.0.0.4"",
                ""access"": ""Allow"",
                ""priority"": 4096,
                ""direction"": ""Inbound"",
                ""sourcePortRanges"": [],
                ""destinationPortRanges"": [],
                ""sourceAddressPrefixes"": [],
                ""destinationAddressPrefixes"": []
            }
        }");

        var fieldElement = fieldDocument.RootElement.GetProperty("field");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.ExecutePropertyEvaluation(fieldElement.GetString(), fieldDocument.RootElement, test.RootElement);

        // Assert
        Assert.True(evaluationResult.Condition);
    }

    [Fact]
    public void NetworkSecurityGroupArrayFieldValidationTest()
    {
        // Arrange
        var fieldDocument = JsonDocument.Parse(@"{
            ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].destinationAddressPrefix"",
            ""equals"": ""10.0.0.4""
        }");
        var test = JsonDocument.Parse(BasicResources.NSG_AllowSSHandRDP);

        var fieldElement = fieldDocument.RootElement.GetProperty("field");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.ExecutePropertyEvaluation(fieldElement.GetString(), fieldDocument.RootElement, test.RootElement);

        // Assert
        Assert.True(evaluationResult.Condition);
    }

    [Fact]
    public void DenyPortsPolicyWithNetworkSecurityGroupTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.Audit;
        var policy = BasicResources.Policy_NSG_DenyPorts;
        var test = BasicResources.NSG_AllowSSHandRDP;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.True(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }


    [Fact]
    public void DenyPortsPolicyWithSecurityRuleTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.Audit;
        var policy = BasicResources.Policy_NSG_DenyPorts;
        var test = BasicResources.SecurityRule_AllowSSH;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.True(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }

    [Fact]
    public void LocationPolicyTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.None;
        var policy = BasicResources.Policy_Location_List;
        var test = BasicResources.NSG_AllowSSHandRDP;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }
}