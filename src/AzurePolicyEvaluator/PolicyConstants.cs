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
        public const string Name = "Parameters";
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
        // TODO: Add more conditions from: https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure#conditions
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
}
