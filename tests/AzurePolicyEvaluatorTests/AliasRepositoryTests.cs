using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class AliasRepositoryTests
{
    [Theory]
    [InlineData("Microsoft.ApiManagement/service/sku.name", true, "sku.name")]
    public void AliasTests(string alias, bool expected, string expectedPath)
    {
        // Arrange
        var aliasRepository = new AliasRepository(NullLogger<AliasRepository>.Instance);

        // Act
        var actual = aliasRepository.TryGetAlias(alias, out var actualPath);

        // Assert
        Assert.Equal(expected, actual);
        Assert.Equal(expectedPath, actualPath);
    }

    [Fact]
    public void ApiManagementSkuAliasTest()
    {
        // Arrange
        var fieldDocument = JsonDocument.Parse(@"{
            ""field"": ""Microsoft.ApiManagement/service/sku.name"",
            ""equals"": ""Premium""
        }");
        var test = JsonDocument.Parse(@"{
            ""sku"": {
                ""name"": ""Premium""
            }
        }");

        var fieldElement = fieldDocument.RootElement.GetProperty("field");

        var evaluator = new Evaluator(NullLogger<Evaluator>.Instance, new(NullLogger<AliasRepository>.Instance));

        // Act
        var evaluationResult = evaluator.ExecutePropertyEvaluation(fieldElement.GetString(), fieldDocument.RootElement, test.RootElement);

        // Assert
        Assert.True(evaluationResult.Condition);
    }
}
