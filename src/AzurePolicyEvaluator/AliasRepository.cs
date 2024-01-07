using System.Text.Json;

namespace AzurePolicyEvaluator;

public class AliasRepository
{
    internal Dictionary<string, string> _aliasCache { get; set; } = [];

    //[RequiresUnreferencedCode("Uses JSON deserialization")]
    public bool TryGetAlias(string alias, out string path)
    {
        path = string.Empty;
        if (_aliasCache.ContainsKey(alias))
        {
            path = _aliasCache[alias];
            return true;
        }

        var allPolicyAliases = JsonSerializer.Deserialize<Dictionary<string, string>>(AliasResources.PolicyAliases);
        if (allPolicyAliases.ContainsKey(alias))
        {
            path = allPolicyAliases[alias];
            _aliasCache.Add(alias, path);
            return true;
        }

        return false;
    }
}
