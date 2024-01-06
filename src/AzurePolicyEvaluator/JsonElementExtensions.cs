using System.Text.Json;

namespace AzurePolicyEvaluator;

static class JsonElementExtensions
{
    public static bool TryGetPropertyIgnoreCasing(this JsonElement element, string propertyName, out JsonElement value)
    {
        var members = element.EnumerateObject();
        var member = members.FirstOrDefault(p => p.Name.Equals(propertyName, StringComparison.InvariantCultureIgnoreCase));
        if (member.Value.ValueKind == JsonValueKind.Undefined)
        {
            value = default;
            return false;
        }
        return element.TryGetProperty(member.Name, out value);
    }
}
