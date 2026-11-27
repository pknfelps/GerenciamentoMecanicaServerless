using Amazon.Lambda.APIGatewayEvents;
using GerenciamentoMecanica.Autenticacao.Domain.Users;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal sealed class InternalLoginInput
{
    public string? Name { get; init; }
    public string? Password { get; init; }
    public string? Role { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class InternalUserUpdateInput
{
    private string? name;
    private string? password;
    internal bool NameProvided { get; private set; }
    internal bool PasswordProvided { get; private set; }
    public string? Name { get => name; set { name = value; NameProvided = true; } }
    public string? Password { get => password; set { password = value; PasswordProvided = true; } }
}

internal static class InternalUserRequestParser
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 32 };
    private static readonly Regex NamePattern = new(@"\A[a-zA-ZÀ-ÿ\s]{3,}\z", RegexOptions.NonBacktracking);
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Utf16 = new UnicodeEncoding(false, false, true);

    public static APIGatewayProxyResponse? ParseCredentials(APIGatewayProxyRequest request, string traceId, out InternalLoginInput? input)
    {
        var failure = ReadJson(request, traceId, "user", out input);
        if (input is null)
            return failure;

        var errors = new Dictionary<string, string[]>();
        var nameErrors = CheckNameOrRole(input.Name, "Name");
        var roleErrors = CheckNameOrRole(input.Role, "Role");
        if (!InternalUserRoles.IsValid(input.Role))
            roleErrors.Add("Cargo inválido: informe Admin ou Mechanic");

        if (nameErrors.Count > 0) errors.Add("Name", [.. nameErrors]);
        if (roleErrors.Count > 0) errors.Add("Role", [.. roleErrors]);
        if (string.IsNullOrWhiteSpace(input.Password)) errors.Add("Password", ["The Password field is required."]);
        return errors.Count > 0 ? InternalAuthResponse.ValidationFailure(traceId, errors) : null;
    }

    public static APIGatewayProxyResponse? ParseUpdate(APIGatewayProxyRequest request, string traceId, out InternalUserUpdateInput? input)
    {
        var failure = ReadJson(request, traceId, "request", out input);
        if (input is null)
            return failure;

        var errors = new Dictionary<string, string[]>();
        var nameErrors = new List<string>();
        if (!MatchesNamePattern(input.Name))
            nameErrors.Add("O campo Name deve conter ao menos 3 caracteres");
        if (input.Name is { Length: > 100 })
            nameErrors.Add("The field Name must be a string or array type with a maximum length of '100'.");
        if (nameErrors.Count > 0)
            return InternalAuthResponse.ValidationFailure(traceId, new() { ["Name"] = [.. nameErrors] });

        if (!input.NameProvided && !input.PasswordProvided)
            errors.Add(string.Empty, ["Informe nome ou senha para atualizar a conta."]);
        if (input.NameProvided && string.IsNullOrWhiteSpace(input.Name))
            errors.Add("Name", ["O nome informado deve ser preenchido."]);
        if (input.PasswordProvided && string.IsNullOrWhiteSpace(input.Password))
            errors.Add("Password", ["A senha informada deve ser preenchida."]);
        return errors.Count > 0 ? InternalAuthResponse.ValidationFailure(traceId, errors) : null;
    }

    public static bool MatchesNamePattern(string? value) => string.IsNullOrEmpty(value) || NamePattern.IsMatch(value);

    private static APIGatewayProxyResponse? ReadJson<T>(
        APIGatewayProxyRequest request, string traceId, string parameter, out T? input) where T : class
    {
        input = null;
        var contentTypes = ProxyRequestHeaders.Values(request, "Content-Type").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (contentTypes.Length != 1 || GetJsonEncoding(contentTypes[0]) is not { } encoding)
            return InternalAuthResponse.UnsupportedMediaType(traceId);

        if (!string.IsNullOrEmpty(request.Body))
        {
            try
            {
                var json = request.IsBase64Encoded ? encoding.GetString(Convert.FromBase64String(request.Body)) : request.Body;
                input = JsonSerializer.Deserialize<T>(json, JsonOptions);
            }
            catch (JsonException error)
            {
                // Use known field paths only. The JSON exception can contain request data.
                var field = error.Path?.ToLowerInvariant() is "$.name" or "$.password" or "$.role" or "$.id" ? error.Path! : "$";
                return InvalidBody(traceId, parameter, field, "The JSON body is invalid.");
            }
            catch (Exception error) when (error is FormatException or DecoderFallbackException)
            {
                return InvalidBody(traceId, parameter, "$", "The JSON body is invalid.");
            }
        }

        return input is null ? InvalidBody(traceId, parameter, string.Empty, "A non-empty request body is required.") : null;
    }

    private static List<string> CheckNameOrRole(string? value, string field)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(value))
            errors.Add($"The {field} field is required.");
        if (!MatchesNamePattern(value))
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

    private static APIGatewayProxyResponse InvalidBody(string traceId, string parameter, string field, string message) =>
        InternalAuthResponse.ValidationFailure(traceId, new Dictionary<string, string[]>
        {
            [field] = [message],
            [parameter] = [$"The {parameter} field is required."]
        });
}
