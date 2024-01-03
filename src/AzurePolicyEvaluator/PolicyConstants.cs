using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzurePolicyEvaluator;

public static class PolicyConstants
{
    public static class Properties
    {
        public const string Name = "properties";
        public const string Mode = "mode";
        public const string PolicyRule = "policyRule";
        public const string If = "if";

        public const string ModeSupported = "all";
    }

    public static class Parameters
    {
        public const string Name = "parameters";
        public const string DefaultValue = "defaultValue";
    }

    public static class LogicalOperators
    {
        public const string Not = "not";
        public const string AnyOf = "anyOf";
        public const string AllOf = "allOf";
    }

    public static class Conditions
    {
        public new const string Equals = "equals";
        public const string NotEquals = "notEquals";
        public const string In = "in";
        public const string NotIn = "notIn";
        // TODO: Add more conditions from: https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#conditions
    }

    public static class TemplateFunctions
    {
        // https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions
        public const string StartMarker = "[";
        public const string EndMarker = "]";
        public const string StartFunction = "(";
        public const string EndFunction = ")";
        public const string StringMarker = "'";

        public const string Parameters = "parameters";
        public const string Concat = "concat";
    }

    public static class Effects
    {
        public const string Audit = "Audit";
        public const string Deny = "Deny";
    }

    public const string Then = "then";
    public const string Effect = "effect";
    public const string Field = "field";
    public const string Type = "type";
    public const string ArrayMemberReference = "[*]";
}
