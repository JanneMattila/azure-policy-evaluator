using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AzurePolicyEvaluatorTests;

public class PolicyFileTests
{
    [Fact]
    public void DenyPortsPolicyWithNetworkSecurityGroupTest()
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
    public void DenyPortsPolicyWithSecurityRuleTest()
    {
        // Arrange
        var expected = PolicyConstants.Effects.Audit;
        var policy = BasicResources.Policy_NSG_DenyPorts;
        var test = BasicResources.SecurityRule_AllowSSH;
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

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
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance);

        // Act
        var evaluationResult = evaluator.Evaluate(policy, test);

        // Assert
        Assert.False(evaluationResult.Condition);
        Assert.Equal(expected, evaluationResult.Effect);
    }
}