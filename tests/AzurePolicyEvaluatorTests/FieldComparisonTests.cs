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
    public void ExistsValidationTests(string existsElement, string propertyValue, bool expected)
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

    [Theory]
    [InlineData("like", "*", "abc", true)]
    [InlineData("like", "a*", "abc", true)]
    [InlineData("like", "b*", "abc", false)]
    [InlineData("like", "*a", "cba", true)]
    [InlineData("like", "*b", "cba", false)]
    [InlineData("notLike", "*", "abc", false)]
    [InlineData("notLike", "a*", "abc", false)]
    [InlineData("notLike", "b*", "abc", true)]
    [InlineData("notLike", "*a", "cba", false)]
    [InlineData("notLike", "*b", "cba", true)]
    public void LikeValidationTests(string comparison, string comparisonValue, string propertyValue, bool expected)
    {
        // Arrange
        var policy = JsonDocument.Parse(@"{
            ""field"": ""value"",
            """ + comparison + "\": \"" + comparisonValue + "\"}");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.FieldComparison(policy.RootElement, "value", propertyValue);

        // Assert
        Assert.Equal(expected, evaluationResult.Condition);
    }
}