using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using static AzurePolicyEvaluator.PolicyConstants;

namespace AzurePolicyEvaluator;

public class Evaluator
{
    private readonly ILogger<Evaluator> _logger;
    private List<Parameter> _parameters = [];

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

        if (policyProperties.TryGetProperty(PolicyConstants.Parameters.Name, out var parameters))
        {
            _parameters = ParseParameters(parameters);
            var effectParameter = _parameters.FirstOrDefault(o => string.Compare(o.Name, PolicyConstants.Effect, true) == 0);
            if (effectParameter != null &&
                effectParameter.DefaultValue != null)
            {
                result.Effect = effectParameter.DefaultValue.ToString();
            }
        }

        result = ExecuteEvaluation(PolicyConstants.Properties.If, policyRoot, testDocument.RootElement);

        var effect = result.Condition ? result.Effect : "No effect";
        _logger.LogInformation("Policy evaluation finished with {Condition} causing effect {Effect}", result.Condition, effect);
        return result;
    }

    internal List<Parameter> ParseParameters(JsonElement parameters)
    {
        using var scope = _logger.BeginScope("ParseParameters");
        _logger.LogDebug("Started parsing of parameters");

        var parametersList = new List<Parameter>();
        if (parameters.ValueKind == JsonValueKind.Object)
        {
            foreach (var parameter in parameters.EnumerateObject())
            {
                var typeProperty = parameter.Value.GetProperty(PolicyConstants.Type).GetString();
                var type = typeProperty != null ? typeProperty.ToLower() : "string";
                var parameterObject = new Parameter
                {
                    Name = parameter.Name,
                    Type = type
                };

                _logger.LogDebug("Parsing parameter {Name} of type {Type}", parameter.Name, type);

                var hasDefaultValue = parameter.Value.TryGetProperty(PolicyConstants.Parameters.DefaultValue, out var defaultValue);

                switch (type)
                {
                    case "string":
                        parameterObject.DefaultValue = string.Empty;
                        if (hasDefaultValue)
                        {
                            parameterObject.DefaultValue = defaultValue.GetString();
                        }
                        break;
                    case "int":
                        parameterObject.DefaultValue = 0;
                        if (hasDefaultValue)
                        {
                            parameterObject.DefaultValue = defaultValue.GetInt32();
                        }
                        break;
                    case "bool":
                        parameterObject.DefaultValue = 0;
                        if (hasDefaultValue)
                        {
                            parameterObject.DefaultValue = defaultValue.GetBoolean();
                        }
                        break;
                    case "array":
                        parameterObject.DefaultValue = new List<string>();
                        if (hasDefaultValue)
                        {
                            parameterObject.DefaultValue = defaultValue.EnumerateArray().Select(o => o.GetString()).ToList();
                        }
                        break;
                    case "object":
                        parameterObject.DefaultValue = new Dictionary<string, string>();
                        if (hasDefaultValue)
                        {
                            parameterObject.DefaultValue = defaultValue.EnumerateObject().ToDictionary(o => o.Name, o => o.Value.ToString());
                        }
                        break;
                    default:
                        throw new NotImplementedException($"Parameter type {type} is not implemented.");
                }

                _logger.LogDebug("Parsed default value {Value}", parameterObject.DefaultValue);

                parametersList.Add(parameterObject);
            }
        }

        _logger.LogDebug("Parsed {Count} parameters", parametersList.Count);
        return parametersList;
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
                string? propertyValue;
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
