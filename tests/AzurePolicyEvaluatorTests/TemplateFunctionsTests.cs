using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class TemplateFunctionsTests
{
    [Fact]
    public void ParameterTemplateFunctionTest()
    {
        // Arrange
        var expected = "westus";
        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));
        evaluator._parameters.Add(new Parameter { Name = "location", DefaultValue = "westus" });

        // Act
        var actual = evaluator.RunTemplateFunctions("[parameters('location')]");

        // Assert
        Assert.Equal(expected, actual);
    }

    //[Fact]
    //public void SimpleConcatTest()
    //{
    //    // Arrange
    //    var expected = "abc";
    //    var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

    //    // Act
    //    var actual = evaluator.RunTemplateFunctions("[concat('a','b','c')]");

    //    // Assert
    //    Assert.Equal(expected, actual);
    //}
}