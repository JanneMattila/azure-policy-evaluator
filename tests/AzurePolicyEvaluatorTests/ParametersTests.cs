using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class ParametersTests
{
    [Fact]
    public void ParseStringParameterTest()
    {
        // Arrange
        using var document = JsonDocument.Parse(BasicResources.Policy_NSG_DenyPorts);
        var parameters = document.RootElement.GetProperty("properties").GetProperty("parameters");
        var expectedParameters = 1;
        var expectedName = "effect";
        var expectedValue = "Audit";

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

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

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var parametersList = evaluator.ParseParameters(parameters);

        // Assert
        Assert.Equal(expectedParameters, parametersList.Count);
        Assert.IsType<List<string>>(parametersList[0].DefaultValue);
        var list = parametersList[0].DefaultValue as List<string>;
        Assert.Equal(expectedListSize, list?.Count);
    }
}