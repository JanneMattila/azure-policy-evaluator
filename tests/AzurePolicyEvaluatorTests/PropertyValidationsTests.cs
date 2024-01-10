using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class PropertyValidationsTests
{
    [Fact]
    public void NetworkSecurityGroupPropertyValidationTest()
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
    public void NetworkSecurityGroupArrayPropertyValidationTest()
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
}