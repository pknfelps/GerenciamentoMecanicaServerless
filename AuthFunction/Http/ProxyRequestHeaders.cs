using Amazon.Lambda.APIGatewayEvents;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal static class ProxyRequestHeaders
{
    public static IEnumerable<string> Values(APIGatewayProxyRequest request, string name)
    {
        var single = request.Headers?.Where(header => header.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            .Select(header => header.Value) ?? [];
        var multiple = request.MultiValueHeaders?.Where(header => header.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            .SelectMany(header => header.Value ?? [string.Empty]) ?? [];
        return single.Concat(multiple);
    }
}
