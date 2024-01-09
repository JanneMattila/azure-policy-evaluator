using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;

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

            using var sourceStream = new MemoryStream(AliasResources.PolicyAliases);
            using var targetStream = new MemoryStream();
            using var gzip = new GZipStream(sourceStream, CompressionMode.Decompress);
            gzip.CopyTo(targetStream);

            var encoding = new UTF8Encoding();
            string policyAliases = encoding.GetString(targetStream.ToArray(), 0, targetStream.ToArray().Length);

            foreach (var line in policyAliases.Split(Environment.NewLine))
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
            _logger.LogDebug("Finished alias cache population in {ElapsedMilliseconds} ms and {Count} items", stopwatch.ElapsedMilliseconds, _aliasCache.Count);
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
