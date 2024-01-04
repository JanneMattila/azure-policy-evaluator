using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AzurePolicyEvaluatorTests;

public class CountEvaluationTests
{
    [Fact]
    public void InvalidTypeTest()
    {
        // Arrange
        var fieldDocument = JsonDocument.Parse(@"{
            ""greater"": ""1""
        }");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.ExecuteCountEvaluation(fieldDocument.RootElement, new());

        // Assert
        Assert.False(evaluationResult.Condition);
    }

    [Theory]
    [InlineData("greater", 0, 1, true)]
    [InlineData("greaterOrEquals", 2, 2, true)]
    [InlineData("less", 3, 2, true)]
    [InlineData("lessOrEquals", 2, 2, true)]
    [InlineData("greater", 2, 1, false)]
    [InlineData("greaterOrEquals", 3, 2, false)]
    [InlineData("less", 1, 2, false)]
    [InlineData("lessOrEquals", 1, 2, false)]
    public void CountTest(string operation, int operationValue, int childCount, bool expectedCondition)
    {
        // Arrange
        var operationElement = JsonDocument.Parse($"{{ \"{operation}\": {operationValue} }}");
        var result = new EvaluationResult() { Count = childCount };

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.ExecuteCountEvaluation(operationElement.RootElement, result);

        // Assert
        Assert.Equal(expectedCondition, evaluationResult.Condition);
    }
}