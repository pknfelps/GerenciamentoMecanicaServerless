using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using GerenciamentoMecanica.Auth.Contracts;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Function;
using GerenciamentoMecanica.Autenticacao.Function.Http;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Authentication;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GerenciamentoMecanica.Autenticacao.FunctionTests;

public class InternalLoginHandlerTests
{
    private const string Key = "internal-password-login-test-key-with-32-characters";
    private const string Issuer = "test-issuer";
    private const string Audience = "test-audience";
    private const string Password = "Password only for the unit test";
    private IInternalUserCredentialsStore store = null!;
    private ILambdaContext context = null!;

    [SetUp]
    public void SetUp()
    {
        store = Substitute.For<IInternalUserCredentialsStore>();
        context = Substitute.For<ILambdaContext>();
        context.RemainingTime.Returns(TimeSpan.FromSeconds(15));
        context.Logger.Returns(Substitute.For<ILambdaLogger>());
        context.AwsRequestId.Returns("authentication-test-request");
    }

    [TestCase("Admin", null, "text/plain")]
    [TestCase("Mechanic", "application/json", "application/json")]
    [TestCase("Admin", "text/plain;q=0.1, application/json;q=0.9", "application/json")]
    public async Task EmitsCompatibleJwtFromStoredIdentity(string role, string? accept, string mediaType)
    {
        var userId = Guid.NewGuid();
        const string storedName = "Nome cadastrado";
        store.FindAsync("Nome da requisição", role, Arg.Any<CancellationToken>())
            .Returns(new InternalUserCredentials(userId, storedName, role, Hash(Password)));
        using var handler = Handler();
        var start = DateTime.UtcNow;

        var response = await handler.HandleAsync(Request(Login("Nome da requisição", Password, role), accept), context);

        Assert.That(response.StatusCode, Is.EqualTo(200));
        Assert.That(response.Headers["Cache-Control"], Is.EqualTo("no-store"));
        Assert.That(response.Headers["Content-Type"], Is.EqualTo(mediaType + "; charset=utf-8"));
        var token = mediaType == "application/json" ? JsonSerializer.Deserialize<string>(response.Body) : response.Body;
        var principal = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key)),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        }, out var validatedToken);
        Assert.Multiple(() =>
        {
            Assert.That(((JwtSecurityToken)validatedToken).Header.Alg, Is.EqualTo("HS256"));
            Assert.That(validatedToken.ValidTo, Is.InRange(start.AddMinutes(10).AddSeconds(-1), DateTime.UtcNow.AddMinutes(10)));
            Assert.That(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, Is.EqualTo(userId.ToString()));
            Assert.That(principal.FindFirst(ClaimTypes.Name)?.Value, Is.EqualTo(storedName));
            Assert.That(principal.FindFirst(ClaimTypes.Role)?.Value, Is.EqualTo(role));
        });
        Assert.That(LastLog(), Does.Not.Contain(Password).And.Not.Contain(token!).And.Not.Contain(storedName));
    }

    [TestCase(null)]
    [TestCase("application/json")]
    public async Task MissingAccountWrongPasswordAndInvalidHashGetTheSameUnauthorizedResponse(string? accept)
    {
        store.FindAsync("Existing", "Admin", Arg.Any<CancellationToken>())
            .Returns(new InternalUserCredentials(Guid.NewGuid(), "Existing", "Admin", Hash("Different password")));
        store.FindAsync("Corrupted", "Admin", Arg.Any<CancellationToken>())
            .Returns(new InternalUserCredentials(Guid.NewGuid(), "Corrupted", "Admin", "invalid-stored-hash"));
        using var handler = Handler();
        foreach (var name in new[] { "Missing", "Existing", "Corrupted" })
        {
            var request = Request(Login(name, Password, "Admin"), accept);
            request.Headers["Authorization"] = "Bearer irrelevant-test-token";
            var response = await handler.HandleAsync(request, context);
            Assert.That(response.StatusCode, Is.EqualTo(401));
            Assert.That(response.Headers.Keys, Does.Not.Contain("Retry-After"));
            var message = accept is null ? response.Body : JsonSerializer.Deserialize<string>(response.Body);
            Assert.That(message, Is.EqualTo("Usuário ou senha inválidos"));
            Assert.That(LastLog(), Does.Contain("invalid-credentials").And.Not.Contain(name).And.Not.Contain(Password));
        }
    }

    [TestCase("""{"name":"Admin","password":"test-only","role":"Customer"}""", "Role")]
    [TestCase("""{"name":"Admin","password":"test-only","role":"admin"}""", "Role")]
    [TestCase("""{"name":"Admin","password":"test-only","role":"1"}""", "Role")]
    [TestCase("""{"name":"Admin","password":"test-only","role":"Admin, Mechanic"}""", "Role")]
    [TestCase("""{"name":"Ab","password":"test-only","role":"Admin"}""", "Name")]
    [TestCase("""{"name":"Admin","password":"  ","role":"Admin"}""", "Password")]
    [TestCase("""{"name":"Admin","role":"Admin"}""", "Password")]
    [TestCase("""{"name":123,"password":"test-only","role":"Admin"}""", "$.name")]
    [TestCase("""{"name":"\ud800","password":"test-only","role":"Admin"}""", "$.name")]
    [TestCase("{", "$")]
    [TestCase("null", "")]
    public async Task RejectsInvalidInputAsValidationProblemBeforeLookup(string body, string errorField)
    {
        using var handler = Handler();
        var response = await handler.HandleAsync(Request(body), context);
        Assert.That(response.StatusCode, Is.EqualTo(400));
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("application/problem+json; charset=utf-8"));
        using var problem = JsonDocument.Parse(response.Body);
        Assert.That(problem.RootElement.GetProperty("errors").GetProperty(errorField).GetArrayLength(), Is.GreaterThan(0));
        await store.DidNotReceiveWithAnyArgs().FindAsync(default!, default!, default);
    }

    [Test]
    public async Task PreservesLegacyJsonBindingForCaseDuplicatesAndAdditionalProperties()
    {
        const string body = """{"name":"Other","NAME":"Mechanic","PASSWORD":"Password only for the unit test","ROLE":"Mechanic","extra":{"n":1}}""";
        using var handler = Handler();
        var request = Request(Convert.ToBase64String(Encoding.UTF8.GetBytes(body)));
        request.IsBase64Encoded = true;
        request.Path = "/authentication/";

        var response = await handler.HandleAsync(request, context);

        Assert.That(response.StatusCode, Is.EqualTo(401));
        await store.Received(1).FindAsync("Mechanic", "Mechanic", Arg.Any<CancellationToken>());
    }

    [Test]
    public async Task UnsupportedContentTypeDoesNotQueryTheStore()
    {
        using var handler = Handler();
        var request = Request(Login("Admin", Password, "Admin"));
        request.Headers["Content-Type"] = "text/plain";
        var response = await handler.HandleAsync(request, context);
        Assert.That(response.StatusCode, Is.EqualTo(415));
        await store.DidNotReceiveWithAnyArgs().FindAsync(default!, default!, default);
    }

    [Test]
    public async Task TechnicalFailureDoesNotExposeDatabaseDetailsOrPassword()
    {
        const string privateError = "private database error";
        store.FindAsync("Admin", "Admin", Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<InternalUserCredentials?>(new InvalidOperationException(privateError)));
        using var handler = Handler();
        var response = await handler.HandleAsync(Request(Login("Admin", Password, "Admin")), context);
        Assert.That(response.StatusCode, Is.EqualTo(500));
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("application/json; charset=utf-8"));
        Assert.That(response.Body + LastLog(), Does.Not.Contain(Password).And.Not.Contain(privateError));
        Assert.That(LastLog(), Does.Contain("technical-failure"));
    }

    private FunctionHandler Handler()
    {
        var jwt = new JwtIssuer(Key, Issuer, Audience);
        var useCase = new InternalLoginUseCase(store, new Pbkdf2PasswordVerifier(), (name, role, id) => jwt.Generate(name, role, id));
        return new FunctionHandler(
            (_, _) => throw new AssertionException("Customer code must not be requested."),
            (_, _, _, _) => throw new AssertionException("Customer code must not be verified."),
            internalLogin: useCase.ExecuteAsync);
    }

    private static APIGatewayProxyRequest Request(string body, string? accept = null)
    {
        var headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" };
        if (accept is not null) headers["Accept"] = accept;
        return new APIGatewayProxyRequest { HttpMethod = "POST", Path = AuthenticationRoute.InternalLogin, Headers = headers, Body = body };
    }

    private static string Login(string name, string password, string role) =>
        JsonSerializer.Serialize(new { name, password, role });

    private string LastLog() => (string)context.Logger.ReceivedCalls().Last().GetArguments()[0]!;

    private static string Hash(string password)
    {
        var salt = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var derived = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        return string.Join('$', "pbkdf2-sha256", "100000", Convert.ToBase64String(salt), Convert.ToBase64String(derived));
    }
}
