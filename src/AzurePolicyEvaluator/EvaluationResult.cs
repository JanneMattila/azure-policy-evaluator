using static AzurePolicyEvaluator.PolicyConstants;

namespace AzurePolicyEvaluator;

public class EvaluationResult
{
    public string Effect { get; set; } = Effects.Deny;

    public bool Condition { get; set; } = false;

    public string EvaluationPath { get; set; } = string.Empty;

    public string Result { get; set; } = string.Empty;

    public string Details { get; set; } = string.Empty;
}
