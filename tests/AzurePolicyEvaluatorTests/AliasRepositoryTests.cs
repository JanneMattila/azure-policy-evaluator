namespace AzurePolicyEvaluatorTests;

public class AliasRepositoryTests
{
    [Theory]
    [InlineData("Microsoft.ApiManagement/service/sku.name", true, "sku.name")]
    public void AliasTests(string alias, bool expected, string expectedPath)
    {
        // Arrange
        var aliasRepository = new AliasRepository(); ;

        // Act
        var actual = aliasRepository.TryGetAlias(alias, out var actualPath);

        // Assert
        Assert.Equal(expected, actual);
        Assert.Equal(expectedPath, actualPath);
    }
}
