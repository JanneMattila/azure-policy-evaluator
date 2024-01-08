using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace AzurePolicyEvaluator;

public class AliasRepository
{
    internal Dictionary<string, string> _aliasCache { get; set; } = [];
    private readonly ILogger<AliasRepository> _logger;

    public AliasRepository(ILogger<AliasRepository> logger)
    {
        _logger = logger;
    }

    public bool TryGetAlias(string alias, out string path)
    {
        var aliasLower = alias.ToLower();
        path = string.Empty;

        if (_aliasCache.Count == 0)
        {
            _logger.LogDebug("Started alias cache population");

            var stopwatch = Stopwatch.StartNew();
            foreach (var line in AliasResources.PolicyAliases.Split("\r\n"))
            {
                var aliases = line.Split(',');
                var key = aliases[0].ToLower();
                if (_aliasCache.ContainsKey(key))
                {
                    continue;
                }
                _aliasCache.Add(key, aliases[1]);
            }

            stopwatch.Stop();
            _logger.LogDebug("Finished alias cache population in {ElapsedMilliseconds} ms", stopwatch.ElapsedMilliseconds);
        }

        if (_aliasCache.TryGetValue(aliasLower, out string? value))
        {
            _logger.LogDebug("Alias {Alias} found in cache {Path}", alias, value);

            path = value;
            return true;
        }
        else
        {
            _logger.LogDebug("Alias {Alias} not found in cache", alias);
        }

        return false;
    }
}
