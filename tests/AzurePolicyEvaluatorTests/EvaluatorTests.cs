namespace AzurePolicyEvaluatorTests;

public class EvaluatorTests
{
    [Fact]
    public async void Test1()
    {
        // Arrange
        var policy = string.Empty;
        var test = string.Empty;
        var evaluator = new Evaluator();

        // Act
        var evaluationResult = await evaluator.EvaluateAsync(policy, test);

        // Assert
        Assert.False(evaluationResult.IsSuccess);
    }
}