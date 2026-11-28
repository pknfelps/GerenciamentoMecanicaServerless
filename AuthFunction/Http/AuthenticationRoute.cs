using Amazon.Lambda.APIGatewayEvents;
namespace GerenciamentoMecanica.Autenticacao.Function.Http;

public static class AuthenticationRoute
{
    public const string RequestCode = "/customers/auth/request-code";
    public const string VerifyCode = "/customers/auth/verify-code";
    public const string InternalLogin = "/Authentication";
    public const string InternalUsers = "/Users";
    public const string Unknown = "/customers/auth";
    public static string Resolve(APIGatewayProxyRequest request)
    {
        var path = request.Resource ?? request.Path;
        if (string.Equals(path, InternalLogin, StringComparison.OrdinalIgnoreCase)
            || string.Equals(path, InternalLogin + "/", StringComparison.OrdinalIgnoreCase))
            return InternalLogin;
        if (string.Equals(path, InternalUsers, StringComparison.OrdinalIgnoreCase)
            || string.Equals(path, InternalUsers + "/", StringComparison.OrdinalIgnoreCase))
            return InternalUsers;
        return path switch { RequestCode => RequestCode, VerifyCode => VerifyCode, _ => Unknown };
    }
}
