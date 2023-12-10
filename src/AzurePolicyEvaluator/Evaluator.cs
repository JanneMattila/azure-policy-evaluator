using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using static AzurePolicyEvaluator.PolicyConstants;

namespace AzurePolicyEvaluator;

public class Evaluator
{
    public EvaluationResult Evaluate(string policy, string test)
    {
        var result = new EvaluationResult();
        if (string.IsNullOrWhiteSpace(policy))
        {
            result.Result = EvaluationResultTexts.EmptyPolicyFile;
            return result;
        }
        if (string.IsNullOrWhiteSpace(test))
        {
            result.Result = EvaluationResultTexts.EmptyTestFile;
            return result;
        }

        JsonDocument policyDocument;
        JsonDocument testDocument;

        try
        {
            policyDocument = JsonDocument.Parse(policy);
        }
        catch (Exception ex)
        {
            result.Result = EvaluationResultTexts.PolicyFileIsNotValidJson;
            result.Details = ex.Message;
            return result;
        }

        try
        {
            testDocument = JsonDocument.Parse(test);
        }
        catch (Exception ex)
        {
            result.Result = EvaluationResultTexts.TestFileIsNotValidJson;
            result.Details = ex.Message;
            return result;
        }

        if (!policyDocument.RootElement.TryGetProperty(PolicyConstants.Properties.Name, out var policyProperties))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainProperties;
            return result;
        }

        if (!policyProperties.TryGetProperty(PolicyConstants.Properties.PolicyRule, out var policyRule))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainPolicyRule;
            return result;
        }

        if (!policyRule.TryGetProperty(PolicyConstants.Properties.If, out var policyRoot))
        {
            result.Result = EvaluationResultTexts.PolicyRuleDoesNotContainIf;
            return result;
        }

        result = ExecuteEvaluation(PolicyConstants.Properties.If, policyRoot, testDocument.RootElement);

        return result;
    }

    internal EvaluationResult ExecuteEvaluation(string name, JsonElement policy, JsonElement test)
    {
        var result = new EvaluationResult();

        if (policy.ValueKind == JsonValueKind.Object)
        {
            if (policy.TryGetProperty(PolicyConstants.Field, out var fieldObject))
            {
                result = ExecuteFieldEvaluation(fieldObject, policy, test);
                return result;
            }
            else
            {
                foreach (var property in policy.EnumerateObject())
                {
                    result = ExecuteEvaluation(property.Name, property.Value, test);
                    if (!result.IsSuccess)
                    {
                        return result;
                    }
                }
            }
        }
        else if (policy.ValueKind == JsonValueKind.Array)
        {
            var results = new List<EvaluationResult>();
            foreach (var array in policy.EnumerateArray())
            {
                result = ExecuteEvaluation(string.Empty, array, test);
                results.Add(result);
            }

            switch (name)
            {
                case PolicyConstants.LogicalOperators.Not:
                    result.IsSuccess = !results.First().IsSuccess;
                    if (!result.IsSuccess)
                    {
                        var firstResult = results.First();
                        result.Result = firstResult.Result;
                        result.Details = firstResult.Details;
                    }
                    break;
                case PolicyConstants.LogicalOperators.AnyOf:
                    result.IsSuccess = results.Any(r => r.IsSuccess);
                    if (!result.IsSuccess)
                    {
                        var failedResult = results.Where(r => !r.IsSuccess).First();
                        result.Result = failedResult.Result;
                        result.Details = failedResult.Details;
                    }
                    break;
                case PolicyConstants.LogicalOperators.AllOf:
                    result.IsSuccess = results.All(r => r.IsSuccess);
                    if (!result.IsSuccess)
                    {
                        var failedResult = results.Where(r => !r.IsSuccess).First();
                        result.Result = failedResult.Result;
                        result.Details = failedResult.Details;
                    }
                    break;
                default:
                    throw new NotImplementedException($"Logical operator {name} is not implemented.");
            }
        }

        return result;
    }

    internal EvaluationResult ExecuteFieldEvaluation(JsonElement fieldObject, JsonElement policy, JsonElement test)
    {
        var result = new EvaluationResult();
        var details = string.Empty;
        if (fieldObject.ValueKind == JsonValueKind.String)
        {
            var propertyName = fieldObject.GetString();
            if (!string.IsNullOrEmpty(propertyName))
            {
                var propertyValue = string.Empty;
                if (propertyName.Contains('/'))
                {
                    var type = test.GetProperty(PolicyConstants.Type).GetString();
                    propertyName = propertyName.Substring(type.Length + 1);

                    var properties = test.GetProperty(PolicyConstants.Properties.Name);

                    if (!properties.TryGetProperty(propertyName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        result.IsSuccess = true;
                        return result;
                    }

                    propertyValue = propertyElement.GetString();
                }
                else
                {
                    if (!test.TryGetProperty(propertyName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        result.IsSuccess = true;
                        return result;
                    }

                    propertyValue = propertyElement.GetString();
                }

                if (policy.TryGetProperty(PolicyConstants.Conditions.Equals, out var equalsElement))
                {
                    var equalsValue = equalsElement.GetString();
                    result.IsSuccess = propertyValue != equalsValue;
                    details = $"Property '{propertyName}' \"equals\" '{equalsValue}'.";
                }
                else if (policy.TryGetProperty(PolicyConstants.Conditions.NotEquals, out var notEqualsElement))
                {
                    var notEqualsValue = notEqualsElement.GetString();
                    result.IsSuccess = propertyValue == notEqualsValue;
                    details = $"Property '{propertyName}' \"notEquals\" '{notEqualsValue}'.";
                }
            }
        }
        else
        {
            throw new NotImplementedException($"Field type {fieldObject.ValueKind} is not implemented.");
        }

        if (!result.IsSuccess)
        {
            result.Result = EvaluationResultTexts.FieldEvaluationFailed;
            result.Details = details;
        }
        return result;
    }
}
