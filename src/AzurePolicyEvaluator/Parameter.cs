namespace AzurePolicyEvaluator;

public class Parameter
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public object? DefaultValue { get; set; }
}
