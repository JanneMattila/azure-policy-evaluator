using Microsoft.Extensions.Logging;
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
    private readonly ILogger<Evaluator> _logger;

    public Evaluator(ILogger<Evaluator> logger)
    {
        _logger = logger;
    }

    public EvaluationResult Evaluate(string policy, string test)
    {
        _logger.LogDebug("Started policy evaluation");

        var result = new EvaluationResult();
        if (string.IsNullOrWhiteSpace(policy))
        {
            result.Result = EvaluationResultTexts.EmptyPolicyFile;
            _logger.LogError(result.Result);
            return result;
        }
        if (string.IsNullOrWhiteSpace(test))
        {
            result.Result = EvaluationResultTexts.EmptyTestFile;
            _logger.LogError(result.Result);
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

            _logger.LogError(ex, result.Result);

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

            _logger.LogError(ex, result.Result);

            return result;
        }

        if (!policyDocument.RootElement.TryGetProperty(PolicyConstants.Properties.Name, out var policyProperties))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainProperties;
            _logger.LogError(result.Result);
            return result;
        }

        if (!policyProperties.TryGetProperty(PolicyConstants.Properties.PolicyRule, out var policyRule))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainPolicyRule;
            _logger.LogError(result.Result);
            return result;
        }

        if (!policyRule.TryGetProperty(PolicyConstants.Properties.If, out var policyRoot))
        {
            result.Result = EvaluationResultTexts.PolicyRuleDoesNotContainIf;
            _logger.LogError(result.Result);
            return result;
        }

        result = ExecuteEvaluation(PolicyConstants.Properties.If, policyRoot, testDocument.RootElement);

        var effect = result.Condition ? result.Effect : "No effect";
        _logger.LogInformation("Policy evaluation finished with {Condition} causing effect {Effect}", result.Condition, effect);
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
                    if (!result.Condition)
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
                case LogicalOperators.Not:
                    if (results.Count != 1)
                    {
                        var error = $"Logical operator {name} must have exactly one child.";
                        _logger.LogError(error);
                        return result;
                    }

                    var firstResult = results.First();
                    result.Condition = !firstResult.Condition;
                    break;
                case LogicalOperators.AnyOf:
                    result.Condition = results.Any(r => r.Condition);
                    if (!result.Condition)
                    {
                        var failedResult = results.Where(r => !r.Condition).FirstOrDefault();
                        result.Result = failedResult?.Result ?? string.Empty;
                        result.Details = failedResult?.Details ?? string.Empty;
                    }
                    break;
                case LogicalOperators.AllOf:
                    result.Condition = results.All(r => r.Condition);
                    if (!result.Condition)
                    {
                        var failedResult = results.Where(r => !r.Condition).FirstOrDefault();
                        result.Result = failedResult?.Result ?? string.Empty;
                        result.Details = failedResult?.Details ?? string.Empty;
                    }
                    break;
                default:
                    throw new NotImplementedException($"Logical operator {name} is not implemented.");
            }

            _logger.LogDebug("Logical operator {LogicalOperator} updated condition to {Condition}", name, result.Condition);
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
                    _logger.LogDebug("Property {PropertyName} is resource property", propertyName);

                    var type = test.GetProperty(PolicyConstants.Type).GetString();
                    propertyName = propertyName.Substring(type.Length + 1);

                    var properties = test.GetProperty(Properties.Name);

                    if (!properties.TryGetProperty(propertyName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        result.Condition = false;
                        return result;
                    }

                    propertyValue = propertyElement.GetString();
                }
                else
                {
                    if (!test.TryGetProperty(propertyName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        result.Condition = false;
                        return result;
                    }

                    propertyValue = propertyElement.GetString();
                }

                if (policy.TryGetProperty(Conditions.Equals, out var equalsElement))
                {
                    var equalsValue = equalsElement.GetString();
                    result.Condition = propertyValue == equalsValue;
                    _logger.LogDebug("Property {PropertyName} \"equals\" {EqualsValue} is {Condition}", propertyName, equalsValue, result.Condition);
                }
                else if (policy.TryGetProperty(Conditions.NotEquals, out var notEqualsElement))
                {
                    var notEqualsValue = notEqualsElement.GetString();
                    result.Condition = propertyValue != notEqualsValue;

                    _logger.LogDebug("Property {PropertyName} \"notEquals\" {NotEqualsValue} is {Condition}", propertyName, notEqualsValue, result.Condition);
                }
            }
        }
        else
        {
            throw new NotImplementedException($"Field type {fieldObject.ValueKind} is not implemented.");
        }

        return result;
    }
}
