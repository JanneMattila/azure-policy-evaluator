using System.Text.Json;

namespace AzurePolicyEvaluatorTests;

public class JsonElementExtensionsTests
{
    [Fact]
    public void IncorrectFieldNameTest()
    {
        // Arrange
        var json = JsonDocument.Parse(@"{
            ""greater"": ""1""
        }");

        // Act
        var isMatch = json.RootElement
            .TryGetPropertyIgnoreCasing("anotherField", out var value);

        // Assert
        Assert.False(isMatch);
    }

    [Fact]
    public void CorrectFieldNameTest()
    {
        // Arrange
        var json = JsonDocument.Parse(@"{
            ""greater"": ""1""
        }");

        // Act
        var isMatch = json.RootElement
            .TryGetPropertyIgnoreCasing("gReAtEr", out var value);

        // Assert
        Assert.True(isMatch);
    }
}
