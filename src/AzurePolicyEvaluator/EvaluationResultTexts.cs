namespace AzurePolicyEvaluator;

public static class EvaluationResultTexts
{
    public const string EmptyPolicyFile = "Empty policy file";
    public const string EmptyTestFile = "Empty test file";

    public const string PolicyFileIsNotValidJson = "Policy file is not valid JSON";
    public const string TestFileIsNotValidJson = "Test file is not valid JSON";

    public const string PolicyDoesNotContainProperties = "Policy does not contain \"properties\"";
    public const string PolicyDoesNotContainPolicyRule = "Policy does not contain \"policyRule\"";
    public const string PolicyRuleDoesNotContainIf = "Policy rule does not contain \"if\"";
    public const string PolicyRuleDoesNotContainThen = "Policy rule does not contain \"then\"";
    public const string PolicyRuleDoesNotContainEffect = "Policy rule does not contain \"effect\"";

    public const string PolicyModeIsNotSupported = "Policy mode \"all\" is only supported";

    public const string FieldEvaluationFailed = "Field evaluation failed";
}
