using Microsoft.Extensions.Logging.Abstractions;
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
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

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
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
    }
}