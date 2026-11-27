using Dapper;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Observability;
using Npgsql;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Persistence;

public sealed class PostgreSqlInternalUserCredentialsStore(NpgsqlDataSource database, IntegrationMetrics? metrics = null)
    : IInternalUserCredentialsStore
{
    private const string Query = """
        SELECT id, name, role, password AS PasswordHash
        FROM public.users
        WHERE name = @Name AND role = @Role;
        """;

    public async Task<InternalUserCredentials?> FindAsync(string name, string role, CancellationToken cancellationToken)
    {
        await using var connection = await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "connection.open", "application",
            () => database.OpenConnectionAsync(cancellationToken).AsTask(), cancellationToken);

        var command = new CommandDefinition(Query, new { Name = name, Role = role },
            commandTimeout: 5, cancellationToken: cancellationToken);
        return await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleOrDefaultAsync<InternalUserCredentials>(command), cancellationToken);
    }
}
