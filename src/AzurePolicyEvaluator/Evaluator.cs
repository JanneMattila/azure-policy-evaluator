using Microsoft.Extensions.Logging;
using System.Text.Json;
using static AzurePolicyEvaluator.PolicyConstants;
using System.Linq;

namespace AzurePolicyEvaluator;

public class Evaluator
{
    private readonly ILogger<Evaluator> _logger;
    internal List<Parameter> _parameters = [];

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

        if (!policyDocument.RootElement.TryGetPropertyIgnoreCasing(PolicyConstants.Properties.Name, out var policyProperties))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainProperties;
            _logger.LogError(result.Result);
            return result;
        }

        if (!policyProperties.TryGetPropertyIgnoreCasing(PolicyConstants.Properties.PolicyRule, out var policyRule))
        {
            result.Result = EvaluationResultTexts.PolicyDoesNotContainPolicyRule;
            _logger.LogError(result.Result);
            return result;
        }

        if (!policyRule.TryGetPropertyIgnoreCasing(PolicyConstants.Properties.If, out var policyRoot))
        {
            result.Result = EvaluationResultTexts.PolicyRuleDoesNotContainIf;
            _logger.LogError(result.Result);
            return result;
        }

        if (!policyRule.TryGetPropertyIgnoreCasing(PolicyConstants.Then, out var thenElement))
        {
            result.Result = EvaluationResultTexts.PolicyRuleDoesNotContainThen;
            _logger.LogError(result.Result);
            return result;
        }

        if (!thenElement.TryGetPropertyIgnoreCasing(PolicyConstants.Effect, out var effectElement))
        {
            result.Result = EvaluationResultTexts.PolicyRuleDoesNotContainEffect;
            _logger.LogError(result.Result);
            return result;
        }

        if (policyProperties.TryGetPropertyIgnoreCasing(PolicyConstants.Parameters.Name, out var parameters))
        {
            _parameters = ParseParameters(parameters);
            var effectParameter = _parameters.FirstOrDefault(o => string.Compare(o.Name, PolicyConstants.Effect, true) == 0);
            if (effectParameter != null &&
                effectParameter.DefaultValue != null)
            {
                var value = effectParameter.DefaultValue.ToString();
                ArgumentNullException.ThrowIfNull(value);
                result.Effect = value;
            }
        }

        result = ExecuteEvaluation(1, policyRoot, testDocument.RootElement);

        if (result.Condition)
        {
            var effect = effectElement.GetString();
            ArgumentNullException.ThrowIfNull(effect);
            result.Effect = (string)RunTemplateFunctions(effect);
        }
        else
        {
            result.Effect = PolicyConstants.Effects.None;
        }
        _logger.LogDebug("Policy evaluation finished with {Condition} causing effect {Effect}", result.Condition, result.Effect);
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

                var hasDefaultValue = parameter.Value.TryGetPropertyIgnoreCasing(PolicyConstants.Parameters.DefaultValue, out var defaultValue);

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

    internal EvaluationResult ExecuteEvaluation(int level, JsonElement policy, JsonElement test)
    {
        using var scope = _logger.BeginScope(level);
        _logger.LogDebug("Started evaluation");

        var result = new EvaluationResult();

        if (policy.ValueKind == JsonValueKind.Object)
        {
            // TODO: Fix case sensitivity
            if (policy.TryGetPropertyIgnoreCasing(LogicalOperators.Not, out var notObject))
            {
                _logger.LogDebug("'not' started");

                result = ExecuteEvaluation(level + 1, notObject, test);
                result.Condition = !result.Condition;

                _logger.LogDebug($"'not' return condition {result.Condition}");
                return result;
            }
            else if (policy.TryGetPropertyIgnoreCasing(LogicalOperators.AnyOf, out var anyOfObject))
            {
                _logger.LogDebug("'anyOf' started");

                var anyOfChildren = anyOfObject.EnumerateArray();
                if (!anyOfChildren.Any())
                {
                    var error = $"Logical operator {LogicalOperators.AnyOf} must have child elements.";
                    _logger.LogError(error);
                    result.Details = error;
                    return result;
                }

                foreach (var property in anyOfChildren)
                {
                    result = ExecuteEvaluation(level + 1, property, test);
                    if (result.Condition)
                    {
                        break;
                    }
                }

                result.Count = result.Condition ? result.Count : 0;
                _logger.LogDebug("'anyOf' return condition {Condition}", result.Condition);
                return result;
            }
            else if (policy.TryGetPropertyIgnoreCasing(LogicalOperators.AllOf, out var allOfObject))
            {
                _logger.LogDebug("'allOf' started");

                var allOfChildren = allOfObject.EnumerateArray();
                if (!allOfChildren.Any())
                {
                    var error = $"Logical operator {LogicalOperators.AllOf} must have child elements.";
                    _logger.LogError(error);
                    result.Details = error;
                    return result;
                }

                var results = new List<EvaluationResult>();
                foreach (var property in allOfChildren)
                {
                    result = ExecuteEvaluation(level + 1, property, test);
                    results.Add(result);
                }
                result.Condition = results.All(o => o.Condition);
                result.Count = result.Condition ? results.Count : 0;

                _logger.LogDebug("'allOf' return condition {Condition}", result.Condition);
                return result;
            }
            else if (policy.TryGetPropertyIgnoreCasing(PolicyConstants.Count, out var countObject))
            {
                _logger.LogDebug("'count' started");

                // More information:
                // https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#field-count
                if (!countObject.TryGetPropertyIgnoreCasing(PolicyConstants.Field, out var fieldObject))
                {
                    var error = $"Count expression must have 'field' child element.";
                    _logger.LogError(error);
                    result.Details = error;
                    return result;
                }

                var hasWhereProperty = countObject.TryGetPropertyIgnoreCasing(PolicyConstants.Where, out var whereObject);

                result = ExecuteFieldEvaluation(fieldObject, policy, test);
                if (hasWhereProperty)
                {
                    var results = ExecuteEvaluation(level + 1, whereObject, test);
                    result.Condition = results.Condition;
                    result.Count = result.Condition ? results.Count : 0;
                }

                result = ExecuteCountEvaluation(policy, result);

                _logger.LogDebug("'count' return condition {Condition} with {Count}", result.Condition, result.Count);
                return result;
            }
            else if (policy.TryGetPropertyIgnoreCasing(PolicyConstants.Field, out var fieldObject))
            {
                _logger.LogDebug("'field' started");

                result = ExecuteFieldEvaluation(fieldObject, policy, test);

                _logger.LogDebug("'field' return condition {Condition}", result.Condition);
                return result;
            }
            else
            {
                throw new NotImplementedException($"Could not find element to process.");
            }
        }
        else
        {
            throw new NotImplementedException($"Policy for element  kind {policy.ValueKind} is not implemented.");
        }
    }

    internal EvaluationResult ExecuteCountEvaluation(JsonElement countObject, EvaluationResult childResult)
    {
        EvaluationResult result = new();
        if (countObject.TryGetPropertyIgnoreCasing(Conditions.Greater, out var greaterElement))
        {
            if (greaterElement.ValueKind != JsonValueKind.Number)
            {
                var error = $"Count expression 'greater' must be number value.";
                _logger.LogError(error);
                result.Details = error;
                return result;
            }
            var greaterValue = greaterElement.GetInt32();
            result.Condition = childResult.Count > greaterValue;
            _logger.LogDebug("Child count {Count} \"greater\" {Value} is {Condition}", childResult.Count, greaterValue, result.Condition);
        }
        else if (countObject.TryGetPropertyIgnoreCasing(Conditions.GreaterOrEquals, out var greaterOrEqualsElement))
        {
            if (greaterOrEqualsElement.ValueKind != JsonValueKind.Number)
            {
                var error = $"Count expression 'greaterOrEquals' must be number value.";
                _logger.LogError(error);
                result.Details = error;
                return result;
            }
            var greaterOrEqualsValue = greaterOrEqualsElement.GetInt32();
            result.Condition = childResult.Count >= greaterOrEqualsValue;
            _logger.LogDebug("Child count {Count} \"greaterOrEquals\" {Value} is {Condition}", childResult.Count, greaterOrEqualsValue, result.Condition);
        }
        else if (countObject.TryGetPropertyIgnoreCasing(Conditions.Less, out var lessElement))
        {
            if (lessElement.ValueKind != JsonValueKind.Number)
            {
                var error = $"Count expression 'less' must be number value.";
                _logger.LogError(error);
                result.Details = error;
                return result;
            }
            var lessValue = lessElement.GetInt32();
            result.Condition = childResult.Count < lessValue;
            _logger.LogDebug("Child count {Count} \"less\" {Value} is {Condition}", childResult.Count, lessValue, result.Condition);
        }
        else if (countObject.TryGetPropertyIgnoreCasing(Conditions.LessOrEquals, out var lessOrEqualsElement))
        {
            if (lessOrEqualsElement.ValueKind != JsonValueKind.Number)
            {
                var error = $"Count expression 'lessOrEquals' must be number value.";
                _logger.LogError(error);
                result.Details = error;
                return result;
            }
            var lessOrEqualsValue = lessOrEqualsElement.GetInt32();
            result.Condition = childResult.Count <= lessOrEqualsValue;
            _logger.LogDebug("Child count {Count} \"lessOrEquals\" {Value} is {Condition}", childResult.Count, lessOrEqualsValue, result.Condition);
        }
        else
        {
            var error = $"Unknown count condition operator.";
            _logger.LogError(error);
            result.Details = error;
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
                string? propertyValue = null;
                if (propertyName.Contains('/'))
                {
                    _logger.LogDebug("Property {PropertyName} is resource property", propertyName);

                    var type = test.GetProperty(PolicyConstants.Type).GetString();
                    ArgumentNullException.ThrowIfNull(type);

                    if (!propertyName.StartsWith(type))
                    {
                        // Property name does not start with the resource type.
                        result.Condition = false;
                        return result;
                    }

                    propertyName = propertyName.Substring(type.Length + 1);

                    var properties = test.GetProperty(Properties.Name);

                    if (propertyName.Contains(PolicyConstants.ArrayMemberReference))
                    {
                        var results = ExecuteArrayFieldEvaluation(propertyName, properties, fieldObject, policy, test);

                        // From:https://learn.microsoft.com/en-us/azure/governance/policy/how-to/author-policies-for-arrays#referencing-the-array-members-collection
                        result.Condition = results.Any(o => o.Condition);
                        result.Count = results.Count(o => o.Condition);
                        return result;
                    }
                    else
                    {
                        if (!properties.TryGetPropertyIgnoreCasing(propertyName, out var propertyElement))
                        {
                            // No property with the given name exists in the test file.
                            result.Condition = false;
                            return result;
                        }

                        propertyValue = propertyElement.GetString();
                    }
                }
                else
                {
                    if (!test.TryGetPropertyIgnoreCasing(propertyName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        result.Condition = false;
                        return result;
                    }

                    propertyValue = propertyElement.GetString();
                }

                ArgumentNullException.ThrowIfNull(propertyValue);

                result = FieldComparison(policy, propertyName, propertyValue);
            }
        }
        else
        {
            throw new NotImplementedException($"Field type {fieldObject.ValueKind} is not implemented.");
        }

        return result;
    }

    internal EvaluationResult FieldComparison(JsonElement policy, string propertyName, string propertyValue)
    {
        EvaluationResult result = new();
        if (policy.TryGetPropertyIgnoreCasing(Conditions.Equals, out var equalsElement))
        {
            var equalsValue = equalsElement.GetString();
            ArgumentNullException.ThrowIfNull(equalsValue);

            var value = RunTemplateFunctions(equalsValue)?.ToString();
            result.Condition = propertyValue == value;
            _logger.LogDebug("Property {PropertyName} \"equals\" {EqualsValue} is {Condition}", propertyName, equalsValue, result.Condition);
        }
        else if (policy.TryGetPropertyIgnoreCasing(Conditions.NotEquals, out var notEqualsElement))
        {
            var notEqualsValue = notEqualsElement.GetString();
            ArgumentNullException.ThrowIfNull(notEqualsValue);

            var value = RunTemplateFunctions(notEqualsValue)?.ToString();
            result.Condition = propertyValue != value;

            _logger.LogDebug("Property {PropertyName} \"notEquals\" {NotEqualsValue} is {Condition}", propertyName, notEqualsValue, result.Condition);
        }
        else if (policy.TryGetPropertyIgnoreCasing(Conditions.In, out var inElement))
        {
            var inValue = inElement.GetString();
            ArgumentNullException.ThrowIfNull(inValue);

            var list = RunTemplateFunctions(inValue) as List<string>;
            ArgumentNullException.ThrowIfNull(list, nameof(list));
            result.Condition = list.Contains(propertyValue);

            _logger.LogDebug("Property {PropertyName} \"in\" {InValue} is {Condition}", propertyName, inValue, result.Condition);
        }
        else if (policy.TryGetPropertyIgnoreCasing(Conditions.NotIn, out var notInElement))
        {
            var notInValue = notInElement.GetString();
            ArgumentNullException.ThrowIfNull(notInValue);

            var list = RunTemplateFunctions(notInValue) as List<string>;
            ArgumentNullException.ThrowIfNull(list, nameof(list));
            result.Condition = !list.Contains(propertyValue);

            _logger.LogDebug("Property {PropertyName} \"notIn\" {NotInValue} is {Condition}", propertyName, notInValue, result.Condition);
        }
        else
        {
            throw new NotImplementedException($"All comparison operations are not yet implemented.");
        }
        return result;
    }

    internal object RunTemplateFunctions(string text)
    {
        // From: https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions
        if (text.StartsWith(TemplateFunctions.StartMarker))
        {
            text = text.Substring(1, text.Length - 2);

            var startIndex = text.IndexOf(TemplateFunctions.StartFunction);
            var endIndex = text.LastIndexOf(TemplateFunctions.EndFunction);
            var function = text.Substring(0, startIndex);
            var functionParameters = text.Substring(startIndex + 1, endIndex - startIndex - 1);
            var parameters = RunTemplateFunctions(functionParameters);

            switch (function)
            {
                case TemplateFunctions.Parameters:
                    var requiredParameter = _parameters.FirstOrDefault(o => o.Name == parameters.ToString());
                    if (requiredParameter == null)
                    {
                        throw new KeyNotFoundException($"Parameter {parameters} not found.");
                    }
                    ArgumentNullException.ThrowIfNull(requiredParameter.DefaultValue);
                    return requiredParameter.DefaultValue;

                case TemplateFunctions.Concat:
                    var concatParameters = parameters as List<string>;
                    ArgumentNullException.ThrowIfNull(concatParameters);
                    text = string.Join(string.Empty, concatParameters);
                    break;
            }
        }
        else if (text.StartsWith(TemplateFunctions.StringMarker) && text.EndsWith(TemplateFunctions.StringMarker))
        {
            text = text.Substring(1, text.Length - 2);
        }

        return text;
    }

    internal List<EvaluationResult> ExecuteArrayFieldEvaluation(string propertyName, JsonElement propertiesElement, JsonElement fieldObject, JsonElement policy, JsonElement test)
    {
        var results = new List<EvaluationResult>();
        var arrayName = propertyName.Substring(0, propertyName.IndexOf(PolicyConstants.ArrayMemberReference));
        if (!propertiesElement.TryGetPropertyIgnoreCasing(arrayName, out var arrayPropertyElement))
        {
            // No array property with the given name exists in the test file.
            results.Add(new EvaluationResult
            {
                Condition = false
            });
            return results;
        }

        var arrayProperty = arrayPropertyElement.EnumerateArray().ToList();
        if (arrayProperty.Count == 0)
        {
            // No property with the given name exists in the test file.
            results.Add(new EvaluationResult
            {
                Condition = false
            });
            return results;
        }

        var nextName = propertyName.Substring(propertyName.IndexOf(PolicyConstants.ArrayMemberReference) + PolicyConstants.ArrayMemberReference.Length);

        if (nextName.Length == 0)
        {
            // Process array itself
            // According to https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#field-count
            // "all array members with the path of 'field' are evaluated to true"
            results.AddRange(arrayProperty.Select(item => new EvaluationResult() { Condition = true }));
        }
        else
        {
            nextName = nextName.Substring(1);
            if (nextName.Contains(PolicyConstants.ArrayMemberReference))
            {
                // Process nested array
                _logger.LogWarning("nested array processing in work-in-progress");

                foreach (var item in arrayProperty)
                {
                    // TODO: Handle nested arrays and results
                    var result = ExecuteArrayFieldEvaluation(nextName, item, fieldObject, policy, test);
                    results.AddRange(result);
                }
            }
            else
            {
                // Process array members
                foreach (var item in arrayProperty)
                {
                    // TODO: Handle arrays and results
                    string? propertyValue = null;
                    var properties = item.GetProperty(Properties.Name);

                    if (!properties.TryGetPropertyIgnoreCasing(nextName, out var propertyElement))
                    {
                        // No property with the given name exists in the test file.
                        results.Add(new EvaluationResult
                        {
                            Condition = false
                        });
                        continue;
                    }

                    propertyValue = propertyElement.GetString();
                    ArgumentNullException.ThrowIfNull(propertyValue);

                    var result = FieldComparison(policy, nextName, propertyValue);
                    results.Add(result);
                }
            }
        }

        return results;
    }
}
