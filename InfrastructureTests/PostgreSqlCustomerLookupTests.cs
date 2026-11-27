using GerenciamentoMecanica.Autenticacao.Infrastructure.Observability;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using NSubstitute;
using System.Text.Json;
using Dapper;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Domain.Customers;
using GerenciamentoMecanica.Autenticacao.Function;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Configuration;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Persistence;
using Npgsql;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using Testcontainers.PostgreSql;
using PostgreSqlConfiguration = GerenciamentoMecanica.Autenticacao.Infrastructure.Configuration.PostgreSqlConfiguration;

namespace GerenciamentoMecanica.Autenticacao.InfrastructureTests;

[NonParallelizable]
public class PostgreSqlCustomerLookupTests
{
    private const string Cpf = "529.982.247-25";
    private const string Cnpj = "10.359.666/0001-94";

    private static readonly Guid CpfId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid CnpjId = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");

    private readonly PostgreSqlContainer container = new PostgreSqlBuilder("postgres:16.15")
        .WithDatabase("mecanica_identity").WithUsername("postgres").WithPassword("test-only-admin-password").Build();

    private NpgsqlDataSource admin = null!;
    private NpgsqlDataSource authentication = null!;
    private NpgsqlConnectionStringBuilder authenticationSettings = null!;
    private PostgreSqlCustomerLookup lookup = null!;
    private readonly string applicationName = "part3-auth-" + Guid.NewGuid().ToString("N");

    [Test]
    public async Task AbsentCustomerCountsASuccessfulConnectionAndQuery()
    {
        using var listener = new IntegrationMetricListener();
        using var metrics = new IntegrationMetrics();
        var instrumented = new PostgreSqlCustomerLookup(authentication, metrics);

        var customer = await instrumented.FindByDocumentAsync("00000000000", CancellationToken.None);

        Assert.That(customer, Is.Null);
        Assert.That(listener.Measurements.Select(point => point["operation"]), Is.EqualTo(new[] { "connection.open", "command.execute" }));
        Assert.That(listener.Measurements.All(point => Equals(point["outcome"], "success")), Is.True);
    }

    [Test]
    public async Task InvalidPersistedCustomerDoesNotTurnTheQueryIntoADatabaseFailure()
    {
        await ExecuteAdminAsync("""
            ALTER TABLE public.customer_access DROP CONSTRAINT customer_access_record_check;
            UPDATE public.customer_access SET status = 'Unknown' WHERE customer_id = @CpfId;
            """, new { CpfId });
        using var listener = new IntegrationMetricListener();
        using var metrics = new IntegrationMetrics();
        var instrumented = new PostgreSqlCustomerLookup(authentication, metrics);

        Assert.ThrowsAsync<InvalidDataException>(() => instrumented.FindByDocumentAsync(Cpf, CancellationToken.None));

        Assert.That(listener.Measurements.Count, Is.EqualTo(2));
        Assert.That(listener.Measurements.All(point => Equals(point["outcome"], "success")), Is.True);
    }

    [OneTimeSetUp]
    public async Task StartDatabase()
    {
        await container.StartAsync();

        var adminSettings = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            SslMode = SslMode.Disable,
            Pooling = false
        };

        admin = NpgsqlDataSource.Create(adminSettings.ConnectionString);

        await ExecuteAdminAsync("""
                                CREATE ROLE mecanica_auth LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
                                    NOREPLICATION NOBYPASSRLS PASSWORD 'test-only-auth-password';
                                GRANT CONNECT ON DATABASE mecanica_identity TO mecanica_auth;
                                REVOKE ALL ON SCHEMA public FROM PUBLIC;
                                GRANT USAGE ON SCHEMA public TO mecanica_auth;
                                """);

        authenticationSettings = new NpgsqlConnectionStringBuilder(adminSettings.ConnectionString)
        {
            Username = "mecanica_auth",
            Password = "test-only-auth-password",
            ApplicationName = applicationName,
            Timeout = 5,
            CommandTimeout = 5
        };

        authentication = NpgsqlDataSource.Create(authenticationSettings.ConnectionString);
        lookup = new PostgreSqlCustomerLookup(authentication);
    }

    [SetUp]
    public async Task SeedIsolatedFixture()
    {
        await ExecuteAdminAsync("""
                                DROP TABLE IF EXISTS public.customer_access;
                                CREATE TABLE public.customer_access (
                                    customer_id uuid PRIMARY KEY,
                                    name varchar(100),
                                    document varchar(100) UNIQUE,
                                    email varchar(100),
                                    status varchar(8) NOT NULL,
                                    revision bigint NOT NULL CHECK (revision >= 0),
                                    CONSTRAINT customer_access_record_check CHECK (
                                        (status = 'Revoked' AND name IS NULL AND document IS NULL AND email IS NULL)
                                        OR
                                        (status IN ('Active', 'Inactive') AND name IS NOT NULL AND document IS NOT NULL AND email IS NOT NULL)
                                    )
                                );
                                GRANT SELECT (customer_id, name, document, status) ON public.customer_access TO mecanica_auth;
                                """);

        await ExecuteAdminAsync("""
                                INSERT INTO public.customer_access (customer_id, name, document, email, status, revision)
                                VALUES (@CpfId, 'Cliente CPF', @Cpf, 'cpf@example.invalid', 'Active', 0),
                                       (@CnpjId, 'Cliente CNPJ', @Cnpj, 'cnpj@example.invalid', 'Active', 0);
                                """, new { CpfId, Cpf, CnpjId, Cnpj });
    }

    [OneTimeTearDown]
    public async Task StopDatabase()
    {
        if (authentication is not null)
            await authentication.DisposeAsync();

        if (admin is not null)
            await admin.DisposeAsync();

        await container.DisposeAsync();
    }

    private async Task ExecuteAdminAsync(string sql, object? parameters = null)
    {
        await using var connection = await admin.OpenConnectionAsync();
        await connection.ExecuteAsync(sql, parameters);
    }

    private async Task WaitForActivityAsync(string predicate, bool expected)
    {
        var elapsed = Stopwatch.StartNew();

        while (elapsed.Elapsed < TimeSpan.FromSeconds(5))
        {
            await using var observer = await admin.OpenConnectionAsync();

            var count = await observer.ExecuteScalarAsync<int>(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name = @Name " + predicate,
                new { Name = applicationName });

            if ((count > 0) == expected)
                return;

            await Task.Delay(25);
        }

        Assert.Fail("Authentication connection activity did not reach the expected state.");
    }

    private Task AssertNoOpenConnectionsAsync() => WaitForActivityAsync("", false);

    [TestCase(Cpf, "Cliente CPF")]
    [TestCase(Cnpj, "Cliente CNPJ")]
    public async Task QueriesOnlyGrantedColumnsAndClosesConnection(string document, string name)
    {
        var customer = await lookup.FindByDocumentAsync(document, CancellationToken.None);

        Assert.That(customer, Is.Not.Null);

        Assert.Multiple(() =>
        {
            Assert.That(customer!.Document, Is.EqualTo(document));
            Assert.That(customer.Name, Is.EqualTo(name));
            Assert.That(customer.Status, Is.EqualTo(CustomerStatus.Active));
            Assert.That(customer.Id, Is.EqualTo(document == Cpf ? CpfId : CnpjId));
        });

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task AbsentCustomerReturnsNullAndClosesConnection()
    {
        Assert.That(await lookup.FindByDocumentAsync("417.384.220-11", CancellationToken.None), Is.Null);

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task DocumentIsAParameterRatherThanSql()
    {
        Assert.That(await lookup.FindByDocumentAsync("' OR true --", CancellationToken.None), Is.Null);
        Assert.That(await lookup.FindByDocumentAsync(Cpf, CancellationToken.None), Is.Not.Null);

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task InactiveCustomerIsMappedWithoutBeingFilteredOut()
    {
        await ExecuteAdminAsync("UPDATE public.customer_access SET status = 'Inactive' WHERE document = @Document",
            new { Document = Cpf });

        var customer = await lookup.FindByDocumentAsync(Cpf, CancellationToken.None);

        Assert.That(customer!.Status, Is.EqualTo(CustomerStatus.Inactive));
        Assert.That(customer.IsEligible, Is.False);

        await AssertNoOpenConnectionsAsync();
    }

    [TestCase("Deleted")]
    [TestCase("active")]
    [TestCase("")]
    public async Task UnknownStatusIsTechnicalAndConnectionCloses(string status)
    {
        await ExecuteAdminAsync("""
            ALTER TABLE public.customer_access DROP CONSTRAINT customer_access_record_check;
            UPDATE public.customer_access SET status = @Status WHERE document = @Document;
            """, new { Status = status, Document = Cpf });

        Assert.ThrowsAsync<InvalidDataException>(() => lookup.FindByDocumentAsync(Cpf, CancellationToken.None));

        await AssertNoOpenConnectionsAsync();
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task InvalidStoredIdentityIsTechnicalAndConnectionCloses(bool emptyId)
    {
        await ExecuteAdminAsync(emptyId
                ? "UPDATE public.customer_access SET customer_id = @Id WHERE document = @Document"
                : "UPDATE public.customer_access SET name = ' ' WHERE document = @Document",
            new { Id = Guid.Empty, Document = Cpf });

        Assert.ThrowsAsync<InvalidDataException>(() => lookup.FindByDocumentAsync(Cpf, CancellationToken.None));

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task MultipleMatchesAreTechnicalAndConnectionCloses()
    {
        await ExecuteAdminAsync("""
                                ALTER TABLE public.customer_access DROP CONSTRAINT customer_access_document_key;
                                INSERT INTO public.customer_access (customer_id, name, document, email, status, revision)
                                VALUES (@Id, 'Duplicado', @Document, 'duplicate@example.invalid', 'Active', 0);
                                """, new { Id = Guid.NewGuid(), Document = Cpf });

        Assert.ThrowsAsync<InvalidOperationException>(() => lookup.FindByDocumentAsync(Cpf, CancellationToken.None));

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task SqlFailureIsTechnicalAndConnectionCloses()
    {
        await ExecuteAdminAsync("ALTER TABLE public.customer_access DROP COLUMN status");

        Assert.ThrowsAsync<PostgresException>(() => lookup.FindByDocumentAsync(Cpf, CancellationToken.None));

        await AssertNoOpenConnectionsAsync();
    }

    [TestCase("SELECT revision FROM public.customer_access")]
    [TestCase("SELECT email FROM public.customer_access")]
    [TestCase("SELECT * FROM public.customer_access")]
    [TestCase("UPDATE public.customer_access SET name = 'forbidden'")]
    [TestCase("DELETE FROM public.customer_access")]
    [TestCase(
        "INSERT INTO public.customer_access (customer_id, name, document, email, status, revision) VALUES (gen_random_uuid(), 'forbidden', 'forbidden', '', 'Active', 0)")]
    public async Task LookupRoleNeedsOnlyTheGrantedColumnsAndNoWrites(string sql)
    {
        await using (var connection = await authentication.OpenConnectionAsync())
        {
            var error = Assert.ThrowsAsync<PostgresException>(() => connection.ExecuteAsync(sql));
            Assert.That(error!.SqlState, Is.EqualTo(PostgresErrorCodes.InsufficientPrivilege));
        }

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task PreCanceledLookupDoesNotLeaveConnection()
    {
        Assert.CatchAsync<OperationCanceledException>(() =>
            lookup.FindByDocumentAsync(Cpf, new CancellationToken(true)));

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task InFlightCancellationClosesBlockedConnection()
    {
        await using var blocker = await admin.OpenConnectionAsync();
        await using var transaction = await blocker.BeginTransactionAsync();

        await blocker.ExecuteAsync("LOCK TABLE public.customer_access IN ACCESS EXCLUSIVE MODE", transaction: transaction);

        using var cancellation = new CancellationTokenSource();
        var pending = lookup.FindByDocumentAsync(Cpf, cancellation.Token);

        try
        {
            await WaitForActivityAsync("AND wait_event_type = 'Lock'", true);
        }
        finally
        {
            cancellation.Cancel();
        }

        Assert.CatchAsync<OperationCanceledException>(async () => await pending);

        await AssertNoOpenConnectionsAsync();
    }

    [Test]
    public async Task FiveSecondCommandTimeoutClosesBlockedConnection()
    {
        await using var blocker = await admin.OpenConnectionAsync();
        await using var transaction = await blocker.BeginTransactionAsync();

        await blocker.ExecuteAsync("LOCK TABLE public.customer_access IN ACCESS EXCLUSIVE MODE", transaction: transaction);

        var elapsed = Stopwatch.StartNew();
        var error = Assert.ThrowsAsync<NpgsqlException>(() => lookup.FindByDocumentAsync(Cpf, CancellationToken.None));

        Assert.That(error!.InnerException, Is.TypeOf<TimeoutException>());
        Assert.That(elapsed.Elapsed, Is.GreaterThanOrEqualTo(TimeSpan.FromSeconds(4.5)));
        Assert.That(elapsed.Elapsed, Is.LessThan(TimeSpan.FromSeconds(12)));

        await AssertNoOpenConnectionsAsync();
    }

}
