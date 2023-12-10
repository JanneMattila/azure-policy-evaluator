using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class BasicEvaluatorTests
{
    [Fact]
    public void EmptyPolicyFileTest()
    {
        // Arrange
        var policy = string.Empty;
        var test = string.Empty;
        var evaluator = new Evaluator();

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.IsSuccess);
    }

    [Fact]
    public void EmptyTestFileTest()
    {
        // Arrange
        var policy = "{ }";
        var test = string.Empty;
        var evaluator = new Evaluator();

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.IsSuccess);
    }

    [Fact]
    public void NetworkSecurityGroupPolicyTest()
    {
        // Arrange
        var policy = BasicResources.PolicyNetworkSecurityGroup1;
        var test = BasicResources.TestNetworkSecurityGroup1;
        var evaluator = new Evaluator();

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.True(evaluationResult.IsSuccess);
    }

    [Fact]
    public void NetworkSecurityGroupPolicyTest2()
    {
        // Arrange
        var fieldDocument = JsonDocument.Parse(@"{
    ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix"",
    ""notEquals"": ""*""
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

        var evaluator = new Evaluator();

        // Act
        var evaluationResult = evaluator.ExecuteFieldEvaluation(fieldElement, fieldDocument.RootElement, test.RootElement);

        // Assert
        Assert.True(evaluationResult.IsSuccess);
    }
}