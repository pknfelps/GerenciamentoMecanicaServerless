using Amazon.Lambda.APIGatewayEvents;
using System.Net.Http.Headers;
using System.Text.Json;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal static class InternalLoginResponse
{
    private const string PlainText = "text/plain";
    private const string Json = "application/json";
    private const string Problem = "application/problem+json; charset=utf-8";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static APIGatewayProxyResponse FromToken(APIGatewayProxyRequest request, string? token)
    {
        var mediaType = StringMediaType(request);
        var authenticated = !string.IsNullOrEmpty(token);
        var body = authenticated ? token! : "Usuário ou senha inválidos";
        return AuthenticationResponse.Create(authenticated ? 200 : 401, mediaType + "; charset=utf-8",
            mediaType == PlainText ? body : JsonSerializer.Serialize(body, JsonOptions));
    }

    public static APIGatewayProxyResponse ValidationFailure(string traceId, Dictionary<string, string[]> errors) =>
        AuthenticationResponse.Create(400, Problem, JsonSerializer.Serialize(new
        {
            type = "https://tools.ietf.org/html/rfc9110#section-15.5.1",
            title = "One or more validation errors occurred.",
            status = 400,
            errors,
            traceId
        }, JsonOptions));

    public static APIGatewayProxyResponse UnsupportedMediaType(string traceId) =>
        AuthenticationResponse.Create(415, Problem, JsonSerializer.Serialize(new
        {
            type = "https://tools.ietf.org/html/rfc9110#section-15.5.16",
            title = "Unsupported Media Type",
            status = 415,
            traceId
        }, JsonOptions));

    public static APIGatewayProxyResponse TechnicalFailure() =>
        AuthenticationResponse.Create(500, "application/json; charset=utf-8", JsonSerializer.Serialize(new
        {
            title = "Erro interno do servidor",
            status = 500,
            detail = "Ocorreu um erro inesperado ao processar a requisição.",
            instance = AuthenticationRoute.InternalLogin
        }, JsonOptions));

    private static string StringMediaType(APIGatewayProxyRequest request)
    {
        var accepted = ProxyRequestHeaders.Values(request, "Accept")
            .SelectMany(value => value.Split(','))
            .Select(value => MediaTypeWithQualityHeaderValue.TryParse(value, out var mediaType) ? mediaType : null)
            .OfType<MediaTypeWithQualityHeaderValue>().ToArray();
        if (accepted.Any(value => value.MediaType == "*/*"))
            return PlainText;

        foreach (var value in accepted.OrderByDescending(value => value.Quality ?? 1))
        {
            if (value.Quality == 0) continue;
            switch (value.MediaType?.ToLowerInvariant())
            {
                case PlainText or "text/*": return PlainText;
                case Json or "application/*": return Json;
                case "text/json": return "text/json";
            }
        }
        return PlainText;
    }
}
