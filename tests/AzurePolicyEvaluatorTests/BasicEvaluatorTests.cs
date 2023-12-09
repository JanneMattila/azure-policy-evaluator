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
}