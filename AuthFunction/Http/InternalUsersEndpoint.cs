using Amazon.Lambda.APIGatewayEvents;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace GerenciamentoMecanica.Autenticacao.Function.Http;

internal static class InternalUsersEndpoint
{
    public static async Task<APIGatewayProxyResponse> ExecuteAsync(
        APIGatewayProxyRequest request, string traceId, FunctionRuntimeProvider? runtime, CancellationToken cancellationToken)
    {
        if (request.HttpMethod is not ("POST" or "GET" or "PATCH" or "DELETE"))
        {
            var response = Empty(405);
            response.Headers["Allow"] = "DELETE, GET, PATCH, POST";
            return response;
        }

        var headers = ProxyRequestHeaders.Values(request, "Authorization").Distinct(StringComparer.Ordinal).ToArray();
        if (headers.Length != 1 || !AuthenticationHeaderValue.TryParse(headers[0], out var header)
            || !header.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(header.Parameter))
            return Challenge();

        var context = await (runtime ?? throw new InvalidOperationException("Internal users are not configured."))
            .GetRuntimeAsync(cancellationToken);
        var principal = context.InternalUserTokens.Validate(header.Parameter);
        if (principal is null)
            return Challenge();

        var admin = principal.IsInRole("Admin");
        if (!admin && (!principal.IsInRole("Mechanic") || request.HttpMethod is "POST" or "DELETE"))
            return Empty(403);

        var users = context.InternalUsers;
        try
        {
            return request.HttpMethod switch
            {
                "POST" => await RegisterAsync(users, request, traceId, cancellationToken),
                "GET" => await GetAsync(users, request, traceId, principal, admin, cancellationToken),
                "PATCH" => await UpdateAsync(users, request, traceId, principal, cancellationToken),
                _ => await DeleteAsync(users, request, traceId, cancellationToken)
            };
        }
        catch (InternalUserException error)
        {
            var (status, title) = error.Failure switch
            {
                InternalUserFailure.InvalidInput => (400, "Requisição inválida"),
                InternalUserFailure.AccessDenied => (403, "Acesso negado"),
                InternalUserFailure.NotFound => (404, "Recurso não encontrado"),
                InternalUserFailure.Conflict => (409, "Conflito"),
                _ => throw new InvalidOperationException("Unexpected internal user error.")
            };
            return InternalAuthResponse.OperationFailure(AuthenticationRoute.InternalUsers, status, title, error.Message);
        }
    }

    private static async Task<APIGatewayProxyResponse> RegisterAsync(InternalUsersUseCase users,
        APIGatewayProxyRequest request, string traceId, CancellationToken cancellationToken)
    {
        if (InternalUserRequestParser.ParseCredentials(request, traceId, out var input) is { } failure)
            return failure;
        await users.RegisterAsync(input!.Name!, input.Role!, input.Password!, cancellationToken);
        return Empty(201);
    }

    private static async Task<APIGatewayProxyResponse> GetAsync(InternalUsersUseCase users, APIGatewayProxyRequest request,
        string traceId, ClaimsPrincipal principal, bool admin, CancellationToken cancellationToken)
    {
        var name = OptionalFilter(request, "name");
        var role = OptionalFilter(request, "role");
        var errors = new Dictionary<string, string[]>();
        if (!InternalUserRequestParser.MatchesNamePattern(name))
            errors["name"] = ["O campo name deve conter ao menos 3 caracteres"];
        if (!InternalUserRequestParser.MatchesNamePattern(role))
            errors["role"] = ["O campo role deve conter ao menos 3 caracteres"];
        if (errors.Count > 0)
            return InternalAuthResponse.ValidationFailure(traceId, errors);

        var id = Guid.Empty;
        if (!admin && !TryGetId(principal, out id))
            return Challenge();

        var user = admin
            ? await users.FindAsync(name, role, cancellationToken)
            : await users.FindOwnAsync(id, name, role, cancellationToken);
        return user is null ? InternalAuthResponse.UserNotFound(traceId) : InternalAuthResponse.User(request, user);
    }

    private static async Task<APIGatewayProxyResponse> UpdateAsync(InternalUsersUseCase users,
        APIGatewayProxyRequest request, string traceId, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        if (InternalUserRequestParser.ParseUpdate(request, traceId, out var input) is { } failure)
            return failure;
        if (!TryGetId(principal, out var id))
            return Challenge();

        await users.UpdateOwnAsync(id, input!.Name, input.Password, cancellationToken);
        return Empty(204);
    }

    private static async Task<APIGatewayProxyResponse> DeleteAsync(InternalUsersUseCase users,
        APIGatewayProxyRequest request, string traceId, CancellationToken cancellationToken)
    {
        var value = QueryValue(request, "id");
        var parsed = Guid.TryParse(value, out var id);
        if (!parsed || id == Guid.Empty)
        {
            const string required = "A value for the 'id' parameter or property was not provided.";
            string[] errors = value is null ? [required]
                : parsed ? ["O campo id não pode ser um GUID vazio"]
                : ["The value is not a valid GUID.", required];
            return InternalAuthResponse.ValidationFailure(traceId, new() { ["id"] = errors });
        }

        await users.DeleteAsync(id, cancellationToken);
        return Empty(204);
    }

    private static bool TryGetId(ClaimsPrincipal principal, out Guid id)
    {
        id = Guid.Empty;
        var identifiers = principal.FindAll(ClaimTypes.NameIdentifier).ToArray();
        return identifiers is [var claim] && Guid.TryParse(claim.Value, out id) && id != Guid.Empty;
    }

    private static string OptionalFilter(APIGatewayProxyRequest request, string key)
    {
        var value = QueryValue(request, key);
        return string.IsNullOrWhiteSpace(value) ? string.Empty : value;
    }

    private static string? QueryValue(APIGatewayProxyRequest request, string key)
    {
        var values = request.MultiValueQueryStringParameters?.FirstOrDefault(pair =>
            pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Value;
        return values?.FirstOrDefault() ?? request.QueryStringParameters?.FirstOrDefault(pair =>
            pair.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Value;
    }

    private static APIGatewayProxyResponse Empty(int status) => AuthenticationResponse.Create(status, null, string.Empty);

    private static APIGatewayProxyResponse Challenge()
    {
        var response = Empty(401);
        response.Headers["WWW-Authenticate"] = "Bearer";
        return response;
    }
}
