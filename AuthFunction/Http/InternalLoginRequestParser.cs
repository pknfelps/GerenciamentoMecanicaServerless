using Amazon.Lambda.APIGatewayEvents;
using GerenciamentoMecanica.Autenticacao.Domain.Users;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal sealed class InternalLoginInput
{
    public string? Name { get; init; }
    public string? Password { get; init; }
    public string? Role { get; init; }
}

internal static class InternalLoginRequestParser
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 32 };
    private static readonly Regex NamePattern = new(@"\A[a-zA-ZÀ-ÿ\s]{3,}\z", RegexOptions.NonBacktracking);
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Utf16 = new UnicodeEncoding(false, false, true);

    public static APIGatewayProxyResponse? Parse(APIGatewayProxyRequest request, string traceId, out InternalLoginInput? input)
    {
        input = null;
        var contentTypes = ProxyRequestHeaders.Values(request, "Content-Type").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (contentTypes.Length != 1 || GetJsonEncoding(contentTypes[0]) is not { } encoding)
            return InternalLoginResponse.UnsupportedMediaType(traceId);
        if (string.IsNullOrEmpty(request.Body))
            return MissingBody(traceId);

        try
        {
            var json = request.IsBase64Encoded ? encoding.GetString(Convert.FromBase64String(request.Body)) : request.Body;
            input = JsonSerializer.Deserialize<InternalLoginInput>(json, JsonOptions);
        }
        catch (JsonException error)
        {
            // Use known field paths only. The JSON exception can contain request data.
            var field = error.Path?.ToLowerInvariant() is "$.name" or "$.password" or "$.role" ? error.Path : "$";
            return InvalidBody(traceId, field!, "The JSON body is invalid.");
        }
        catch (Exception error) when (error is FormatException or DecoderFallbackException)
        {
            return InvalidBody(traceId, "$", "The JSON body is invalid.");
        }

        if (input is null)
            return MissingBody(traceId);

        var errors = new Dictionary<string, string[]>();
        var nameErrors = CheckNameOrRole(input.Name, "Name");
        var roleErrors = CheckNameOrRole(input.Role, "Role");
        if (!InternalUserRoles.IsValid(input.Role))
            roleErrors.Add("Cargo inválido: informe Admin ou Mechanic");

        if (nameErrors.Count > 0) errors.Add("Name", [.. nameErrors]);
        if (roleErrors.Count > 0) errors.Add("Role", [.. roleErrors]);
        if (string.IsNullOrWhiteSpace(input.Password)) errors.Add("Password", ["The Password field is required."]);
        return errors.Count > 0 ? InternalLoginResponse.ValidationFailure(traceId, errors) : null;
    }

    private static List<string> CheckNameOrRole(string? value, string field)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(value))
            errors.Add($"The {field} field is required.");
        if (!string.IsNullOrEmpty(value) && !NamePattern.IsMatch(value))
            errors.Add($"O campo {field} deve conter ao menos 3 caracteres");
        return errors;
    }

    private static Encoding? GetJsonEncoding(string value)
    {
        if (!MediaTypeHeaderValue.TryParse(value, out var contentType) || contentType.MediaType is null)
            return null;
        var mediaType = contentType.MediaType.ToLowerInvariant();
        if (mediaType is not ("application/json" or "text/json")
            && !(mediaType.StartsWith("application/", StringComparison.Ordinal) && mediaType.EndsWith("+json", StringComparison.Ordinal)))
            return null;
        return contentType.CharSet?.Trim('"').ToLowerInvariant() switch
        {
            null or "" or "utf-8" => Utf8,
            "utf-16" => Utf16,
            _ => null
        };
    }

    private static APIGatewayProxyResponse MissingBody(string traceId) =>
        InvalidBody(traceId, string.Empty, "A non-empty request body is required.");

    private static APIGatewayProxyResponse InvalidBody(string traceId, string field, string message) =>
        InternalLoginResponse.ValidationFailure(traceId, new Dictionary<string, string[]>
        {
            [field] = [message],
            ["user"] = ["The user field is required."]
        });
}
