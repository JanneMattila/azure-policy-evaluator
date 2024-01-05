using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AzurePolicyEvaluatorTests;

public class BasicEvaluatorTests
{
    [Fact]
    public void EmptyPolicyFileTest()
    {
        // Arrange
        var policy = string.Empty;
        var test = string.Empty;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
    }

    [Fact]
    public void EmptyTestFileTest()
    {
        // Arrange
        var policy = "{ }";
        var test = string.Empty;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
    }

    [Fact]
    public void ParseStringParameterTest()
    {
        // Arrange
        using var document = JsonDocument.Parse(BasicResources.Policy_NSG_DenyPorts);
        var parameters = document.RootElement.GetProperty("properties").GetProperty("parameters");
        var expectedParameters = 1;
        var expectedName = "effect";
        var expectedValue = "Audit";

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var parametersList = evaluator.ParseParameters(parameters);

        // Assert
        Assert.Equal(expectedParameters, parametersList.Count);
        Assert.Equal(expectedName, parametersList[0].Name);
        Assert.Equal(expectedValue, parametersList[0].DefaultValue);
    }

    [Fact]
    public void ParseArrayParameterTest()
    {
        // Arrange
        using var document = JsonDocument.Parse(BasicResources.Policy_Location_List);
        var parameters = document.RootElement.GetProperty("properties").GetProperty("parameters");
        var expectedParameters = 1;
        var expectedListSize = 2;

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var parametersList = evaluator.ParseParameters(parameters);

        // Assert
        Assert.Equal(expectedParameters, parametersList.Count);
        Assert.IsType<List<string>>(parametersList[0].DefaultValue);
        var list = parametersList[0].DefaultValue as List<string>;
        Assert.Equal(expectedListSize, list?.Count);
    }

    [Fact]
    public void LocationPolicyTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.None;
        var policy = BasicResources.Policy_Location_List;
        var test = BasicResources.NSG_AllowSSHandRDP;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }

    [Fact]
    public void ParameterTemplateFunctionTest()
    {
        // Arrange
        var expected = "westus";
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);
        evaluator._parameters.Add(new Parameter { Name = "location", DefaultValue = "westus" });

        // Act
        var actual = evaluator.RunTemplateFunctions("[parameters('location')]");

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void NetworkSecurityGroupPolicyTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.Audit;
        var policy = BasicResources.Policy_NSG_DenyPorts;
        var test = BasicResources.NSG_AllowSSHandRDP;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.True(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }

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

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.ExecuteFieldEvaluation(fieldElement, fieldDocument.RootElement, test.RootElement);

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

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.ExecuteFieldEvaluation(fieldElement, fieldDocument.RootElement, test.RootElement);

        // Assert
        Assert.True(evaluationResult.Condition);
    }
}