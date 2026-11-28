using Amazon.Lambda.APIGatewayEvents;
using GerenciamentoMecanica.Autenticacao.Domain.Users;
using System.Net.Http.Headers;
using System.Text.Json;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal static class InternalAuthResponse
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

    public static APIGatewayProxyResponse TechnicalFailure(string route) =>
        OperationFailure(route, 500, "Erro interno do servidor", "Ocorreu um erro inesperado ao processar a requisição.");

    public static APIGatewayProxyResponse OperationFailure(string route, int status, string title, string detail) =>
        AuthenticationResponse.Create(status, "application/json; charset=utf-8", JsonSerializer.Serialize(new
        {
            title,
            status,
            detail,
            instance = route
        }, JsonOptions));

    public static APIGatewayProxyResponse UserNotFound(string traceId) =>
        AuthenticationResponse.Create(404, Problem, JsonSerializer.Serialize(new
        {
            type = "https://tools.ietf.org/html/rfc9110#section-15.5.5",
            title = "Not Found",
            status = 404,
            traceId
        }, JsonOptions));

    public static APIGatewayProxyResponse User(APIGatewayProxyRequest request, InternalUser user)
    {
        var mediaType = StringMediaType(request) == "text/json" ? "text/json" : Json;
        return AuthenticationResponse.Create(200, mediaType + "; charset=utf-8", JsonSerializer.Serialize(user, JsonOptions));
    }

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
