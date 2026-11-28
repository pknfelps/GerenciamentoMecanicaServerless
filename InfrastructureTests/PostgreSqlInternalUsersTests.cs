using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using GerenciamentoMecanica.Auth.Contracts;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Function;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Configuration;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using NSubstitute;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using PostgreSqlBuilder = Testcontainers.PostgreSql.PostgreSqlBuilder;
using PostgreSqlContainer = Testcontainers.PostgreSql.PostgreSqlContainer;

namespace GerenciamentoMecanica.Autenticacao.InfrastructureTests;

public sealed class PostgreSqlInternalUsersTests
{
    private const string SigningKey = "local-auth06-signing-key-long-enough-for-algorithm-validation-tests";
    private const string Issuer = "test-issuer";
    private const string Audience = "test-audience";
    private const string InitialPassword = "Initial@Test123";
    private const string NewPassword = "Updated@Test456";
    private const string DatabaseUser = "mecanica_auth";
    private const string DatabasePassword = "local-test-only-internal-users-role";
    private readonly PostgreSqlContainer container = new PostgreSqlBuilder("postgres:16.15")
        .WithDatabase("mecanica_identity").Build();
    private FunctionHandler handler = null!;
    private ILambdaContext context = null!;

    [OneTimeSetUp]
    public async Task StartDatabase()
    {
        await container.StartAsync();
        const string sql = """
            CREATE TABLE IF NOT EXISTS public.users (
                id uuid PRIMARY KEY, name varchar(100) NOT NULL, role varchar(100) NOT NULL, password varchar(100) NOT NULL
            );
            CREATE ROLE mecanica_auth LOGIN;
            REVOKE CONNECT ON DATABASE mecanica_identity FROM PUBLIC;
            GRANT CONNECT ON DATABASE mecanica_identity TO mecanica_auth;
            GRANT USAGE ON SCHEMA public TO mecanica_auth;
            GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO mecanica_auth;
            """;
        await using var connection = new NpgsqlConnection(container.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
        await using var configure = new NpgsqlCommand($"ALTER ROLE mecanica_auth PASSWORD '{DatabasePassword}';", connection);
        await configure.ExecuteNonQueryAsync();
    }

    [OneTimeTearDown]
    public async Task StopDatabase() => await container.DisposeAsync();

    [SetUp]
    public void SetUp()
    {
        var connection = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Username = DatabaseUser, Password = DatabasePassword, Pooling = false, Timeout = 5
        };
        var config = new RuntimeConfiguration(new JwtConfiguration(SigningKey, Issuer, Audience), new PostgreSqlConfiguration(connection));
        var sender = Substitute.For<ICustomerCodeSender>();
        handler = new FunctionHandler(new FunctionRuntimeProvider(_ => Task.FromResult(new FunctionRuntime(config, sender: sender))));
        context = Substitute.For<ILambdaContext>();
        context.RemainingTime.Returns(TimeSpan.FromSeconds(15));
        context.Logger.Returns(Substitute.For<ILambdaLogger>());
    }

    [TearDown]
    public async Task DisposeHandler() => await handler.DisposeAsync();

    [Test]
    public async Task AccountLifecyclePreservesOwnershipRoleIdAndOmittedFields()
    {
        const string name = "Conta Oficina";
        const string renamed = "Conta Revisada";
        var admin = Token("Admin");
        var account = await RegisterAsync(name, "Mechanic", admin);
        await using var database = new NpgsqlConnection(container.GetConnectionString());
        await database.OpenAsync();
        await using var readHash = new NpgsqlCommand("SELECT password FROM public.users WHERE id = @id", database);
        readHash.Parameters.AddWithValue("id", account.Id);
        var storedHash = (string)(await readHash.ExecuteScalarAsync())!;
        var mechanic = await LoginAsync(name, InitialPassword, "Mechanic");

        var own = await RequestAsync("GET", mechanic);
        Assert.That(ReadAccount(own), Is.EqualTo(account));
        Assert.That(own.Body, Does.Not.Contain(InitialPassword).And.Not.Contain("password"));
        Assert.That((await RequestAsync("GET", mechanic, query: Filters("Outra Conta", "Mechanic"))).StatusCode, Is.EqualTo(403));
        Assert.That((await RequestAsync("POST", mechanic, new { name = "Conta Proibida", role = "Admin", password = InitialPassword })).StatusCode,
            Is.EqualTo(403));
        Assert.That((await RequestAsync("DELETE", mechanic, query: UserId(account.Id))).StatusCode, Is.EqualTo(403));

        var rename = await RequestAsync("PATCH", mechanic, new { name = renamed }, query: UserId(Guid.NewGuid()));
        Assert.That(rename.StatusCode, Is.EqualTo(204));
        Assert.That(rename.Body, Is.Empty);
        Assert.That(ReadAccount(await RequestAsync("GET", admin, query: Filters(renamed, "Mechanic"))),
            Is.EqualTo((account.Id, renamed, "Mechanic")));
        await LoginAsync(renamed, InitialPassword, "Mechanic");

        Assert.That((await RequestAsync("PATCH", mechanic, new { password = NewPassword })).StatusCode, Is.EqualTo(204));
        var oldPassword = await LoginResponseAsync(renamed, InitialPassword, "Mechanic");
        Assert.That(oldPassword.StatusCode, Is.EqualTo(401));
        await LoginAsync(renamed, NewPassword, "Mechanic");
        Assert.That(ReadAccount(await RequestAsync("GET", mechanic)), Is.EqualTo((account.Id, renamed, "Mechanic")));

        Assert.That((await RequestAsync("DELETE", admin, query: UserId(account.Id))).StatusCode, Is.EqualTo(204));
        Assert.That((await RequestAsync("GET", admin, query: Filters(renamed, "Mechanic"))).StatusCode, Is.EqualTo(404));
        Assert.That((await RequestAsync("GET", mechanic)).StatusCode, Is.EqualTo(404));

        var logs = context.Logger.ReceivedCalls().Select(call => (string)call.GetArguments()[0]!).ToArray();
        var accounts = logs.Select(line =>
        {
            using var json = JsonDocument.Parse(line);
            return json.RootElement.Clone();
        }).Where(log => log.GetProperty("http.route").GetString() == "/Users").ToArray();
        var successfulMethods = accounts.Where(log => log.GetProperty("category").GetString() == "success")
            .Select(log => log.GetProperty("http.request.method").GetString()).Distinct();
        Assert.Multiple(() =>
        {
            Assert.That(successfulMethods, Is.EquivalentTo(new[] { "POST", "GET", "PATCH", "DELETE" }));
            Assert.That(accounts.Select(log => log.GetProperty("category").GetString()), Does.Contain("access-denied").And.Contain("user-not-found"));
            Assert.That(string.Join("\n", logs), Does.Not.Contain(name).And.Not.Contain(renamed)
                .And.Not.Contain(InitialPassword).And.Not.Contain(NewPassword).And.Not.Contain(storedHash)
                .And.Not.Contain(admin).And.Not.Contain(mechanic));
        });
    }

    [Test]
    public async Task NameConflictsAreAtomicAndLimitedToTheSameRole()
    {
        const string duplicate = "Conta Concorrente";
        var admin = Token("Admin");
        var input = new { name = duplicate, role = "Mechanic", password = InitialPassword };
        var results = await Task.WhenAll(RequestAsync("POST", admin, input), RequestAsync("POST", admin, input));
        Assert.That(results.Select(result => result.StatusCode).Order(), Is.EqualTo(new[] { 201, 409 }));
        await RegisterAsync(duplicate, "Admin", admin);

        var one = await RegisterAsync("Mecanico Um", "Mechanic", admin);
        var two = await RegisterAsync("Mecanico Dois", "Mechanic", admin);
        const string target = "Alvo Concorrente";
        results = await Task.WhenAll(RequestAsync("PATCH", Token("Mechanic", one.Id), new { name = target }),
            RequestAsync("PATCH", Token("Mechanic", two.Id), new { name = target }));
        Assert.That(results.Select(result => result.StatusCode).Order(), Is.EqualTo(new[] { 204, 409 }));
        Assert.That(ReadAccount(await RequestAsync("GET", admin, query: Filters(target, "Mechanic"))).Name, Is.EqualTo(target));
    }

    [TestCase("GET", "missing", 401)]
    [TestCase("POST", "invalid", 401)]
    [TestCase("PATCH", "expired", 401)]
    [TestCase("DELETE", "wrong-issuer", 401)]
    [TestCase("GET", "wrong-audience", 401)]
    [TestCase("DELETE", "wrong-algorithm", 401)]
    [TestCase("GET", "Customer", 403)]
    [TestCase("PATCH", "Customer", 403)]
    [TestCase("GET", "missing-id", 401)]
    [TestCase("PATCH", "missing-id", 401)]
    [TestCase("PATCH", "duplicate-id", 401)]
    public async Task AuthorizationRejectsUntrustedTokensAndInvalidOwnAccountIdentities(string method, string scenario, int status)
    {
        var body = method == "PATCH" ? new { name = "Conta Teste" } : null;
        var response = await RequestAsync(method, AuthorizationToken(scenario), body);
        Assert.That(response.StatusCode, Is.EqualTo(status));
        Assert.That(response.Body, Is.Empty);
        Assert.That(response.Headers.ContainsKey("WWW-Authenticate"), Is.EqualTo(status == 401));
    }

    [TestCase("{}")]
    [TestCase("""{"name":null}""")]
    [TestCase("""{"password":" "}""")]
    [TestCase("""{"name":"Conta Teste","id":"33333333-3333-3333-3333-333333333333"}""")]
    [TestCase("""{"name":"Conta Teste","role":"Admin"}""")]
    [TestCase("""{"name":"Conta Teste","other":true}""")]
    public async Task PatchRejectsEmptyUpdatesAndFieldsOutsideTheContract(string json)
    {
        var response = await RequestAsync("PATCH", Token("Admin", Guid.NewGuid()), rawBody: json);
        Assert.That(response.StatusCode, Is.EqualTo(400));
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("application/problem+json; charset=utf-8"));
    }

    [Test]
    public async Task KeepsPasswordPolicyAndDoesNotReadDeleteIdFromBody()
    {
        var admin = Token("Admin");
        var weak = await RequestAsync("POST", admin, new { name = "Conta Senha", role = "Mechanic", password = "weak" });
        Assert.That(weak.StatusCode, Is.EqualTo(400));
        Assert.That(weak.Body, Does.Contain("Senha deve conter pelo menos 6 caracteres").And.Not.Contain("weak"));
        var delete = await RequestAsync("DELETE", admin, new { id = Guid.NewGuid() });
        Assert.That(delete.StatusCode, Is.EqualTo(400));
    }

    private static string Token(string role, Guid? id = null) => new JwtIssuer(SigningKey, Issuer, Audience).Generate("Test Account", role, id);

    private static string? AuthorizationToken(string scenario)
    {
        if (scenario == "missing") return null;
        if (scenario == "invalid") return "invalid-token";
        if (scenario == "Customer") return Token("Customer", Guid.NewGuid());
        if (scenario == "missing-id") return Token("Mechanic");
        var claims = new List<Claim> { new(ClaimTypes.Role, "Admin"), new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) };
        if (scenario == "duplicate-id") claims.Add(new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()));
        var jwt = new JwtSecurityToken(scenario == "wrong-issuer" ? "wrong" : Issuer,
            scenario == "wrong-audience" ? "wrong" : Audience, claims,
            expires: DateTime.UtcNow.AddMinutes(scenario == "expired" ? -1 : 10),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKey)),
                scenario == "wrong-algorithm" ? SecurityAlgorithms.HmacSha384 : SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private async Task<(Guid Id, string Name, string Role)> RegisterAsync(string name, string role, string admin)
    {
        var registered = await RequestAsync("POST", admin, new { name, role, password = InitialPassword });
        Assert.That(registered.StatusCode, Is.EqualTo(201));
        Assert.That(registered.Body, Is.Empty);
        return ReadAccount(await RequestAsync("GET", admin, query: Filters(name, role)));
    }

    private async Task<string> LoginAsync(string name, string password, string role)
    {
        var login = await LoginResponseAsync(name, password, role);
        Assert.That(login.StatusCode, Is.EqualTo(200));
        return login.Body;
    }

    private Task<APIGatewayProxyResponse> LoginResponseAsync(string name, string password, string role) =>
        RequestAsync("POST", null, new { name, password, role }, path: "/Authentication");

    private Task<APIGatewayProxyResponse> RequestAsync(string method, string? token, object? body = null,
        Dictionary<string, string>? query = null, string path = "/Users", string? rawBody = null)
    {
        var headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" };
        if (token is not null) headers["Authorization"] = "Bearer " + token;
        return handler.HandleAsync(new APIGatewayProxyRequest
        {
            Path = path, HttpMethod = method, Headers = headers,
            Body = rawBody ?? (body is null ? null : JsonSerializer.Serialize(body)), QueryStringParameters = query
        }, context);
    }

    private static Dictionary<string, string> Filters(string name, string role) => new() { ["name"] = name, ["role"] = role };
    private static Dictionary<string, string> UserId(Guid id) => new() { ["id"] = id.ToString() };

    private static (Guid Id, string Name, string Role) ReadAccount(APIGatewayProxyResponse response)
    {
        Assert.That(response.StatusCode, Is.EqualTo(200));
        using var body = JsonDocument.Parse(response.Body);
        var user = body.RootElement;
        Assert.That(user.EnumerateObject().Count(), Is.EqualTo(3));
        return (user.GetProperty("id").GetGuid(), user.GetProperty("name").GetString()!, user.GetProperty("role").GetString()!);
    }
}
