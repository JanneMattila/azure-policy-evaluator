using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class FieldComparisonTests
{
    [Fact]
    public void InListValidationTest()
    {
        // Arrange
        var policy = JsonDocument.Parse(@"{
            ""field"": ""value"",
            ""in"": [""aa"", ""bb"", ""cc""]
        }");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.FieldComparison(policy.RootElement, "value", "bb");

        // Assert
        Assert.True(evaluationResult.Condition);
    }

    [Theory]
    [InlineData("true", "a", true)]
    [InlineData("true", "", false)]
    [InlineData("false", "a", false)]
    [InlineData("false", "", true)]
    public void ExistsValidationTest(string existsElement, string propertyValue, bool expected)
    {
        // Arrange
        var policy = JsonDocument.Parse(@"{
            ""field"": ""value"",
            ""exists"": """ + existsElement + "\"}");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.FieldComparison(policy.RootElement, "value", propertyValue);

        // Assert
        Assert.Equal(expected, evaluationResult.Condition);
    }
}