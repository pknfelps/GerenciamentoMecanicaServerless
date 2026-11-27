using System.Data;
using Dapper;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Domain.Users;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Observability;
using Npgsql;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Persistence;

public sealed class PostgreSqlInternalUserStore(NpgsqlDataSource database, IntegrationMetrics? metrics = null)
    : IInternalUserCredentialsStore, IInternalUserStore
{
    private const string CredentialsQuery = """
        SELECT id, name, role, password AS PasswordHash
        FROM public.users
        WHERE name = @Name AND role = @Role;
        """;

    private const string ByName = """
        SELECT id, name, role FROM public.users WHERE name = @Name AND role = @Role;
        """;

    private const string ById = """
        SELECT id, name, role FROM public.users WHERE id = @Id;
        """;

    public async Task<InternalUserCredentials?> FindAsync(string name, string role, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadAsync<InternalUserCredentials>(connection, null, CredentialsQuery, new { Name = name, Role = role }, cancellationToken);
    }

    public async Task<InternalUser?> FindUserAsync(string name, string role, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadAsync<InternalUser>(connection, null, ByName, new { Name = name, Role = role }, cancellationToken);
    }

    public async Task<InternalUser?> FindUserByIdAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadAsync<InternalUser>(connection, null, ById, new { Id = id }, cancellationToken);
    }

    public Task<bool> TryCreateAsync(InternalUser user, Func<string> hashPassword, CancellationToken cancellationToken) =>
        WithWriteLockAsync(async (connection, transaction) =>
        {
            if (await ReadAsync<InternalUser>(connection, transaction, ByName, new { user.Name, user.Role }, cancellationToken) is not null)
                return false;

            const string insert = "INSERT INTO public.users(id, name, role, password) VALUES (@Id, @Name, @Role, @PasswordHash);";
            var affected = await RunAsync(connection, transaction, insert,
                new { user.Id, user.Name, user.Role, PasswordHash = hashPassword() }, cancellationToken);
            if (affected != 1)
                throw new InvalidOperationException("The internal user was not inserted.");
            return true;
        }, cancellationToken);

    public Task<InternalUserUpdateResult> UpdateAsync(Guid id, string? name, Func<InternalUser, string>? hashPassword,
        CancellationToken cancellationToken) =>
        WithWriteLockAsync(async (connection, transaction) =>
        {
            var current = await ReadAsync<InternalUser>(connection, transaction, ById, new { Id = id }, cancellationToken);
            if (current is null)
                return InternalUserUpdateResult.NotFound;

            if (name is not null &&
                await ReadAsync<InternalUser>(connection, transaction, ByName, new { Name = name, current.Role }, cancellationToken) is { } other
                && other.Id != id)
                return InternalUserUpdateResult.Conflict;

            var password = hashPassword?.Invoke(current with { Name = name ?? current.Name });
            const string update = """
                UPDATE public.users SET name = COALESCE(@Name, name), password = COALESCE(@PasswordHash, password)
                WHERE id = @Id;
                """;
            var affected = await RunAsync(connection, transaction, update,
                new { Id = id, Name = name, PasswordHash = password }, cancellationToken);
            return affected == 1 ? InternalUserUpdateResult.Updated : InternalUserUpdateResult.NotFound;
        }, cancellationToken);

    public async Task<bool> TryDeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await RunAsync(connection, null, "DELETE FROM public.users WHERE id = @Id;", new { Id = id }, cancellationToken) == 1;
    }

    private Task<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken) =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "connection.open", "application",
            () => database.OpenConnectionAsync(cancellationToken).AsTask(), cancellationToken);

    private Task<T?> ReadAsync<T>(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, object parameters,
        CancellationToken cancellationToken) where T : class
    {
        var command = new CommandDefinition(sql, parameters, transaction, commandTimeout: 5, cancellationToken: cancellationToken);
        return IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleOrDefaultAsync<T>(command), cancellationToken);
    }

    private Task<int> RunAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, object? parameters,
        CancellationToken cancellationToken)
    {
        var command = new CommandDefinition(sql, parameters, transaction, commandTimeout: 5, cancellationToken: cancellationToken);
        return IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.ExecuteAsync(command), cancellationToken);
    }

    private async Task<T> WithWriteLockAsync<T>(Func<NpgsqlConnection, NpgsqlTransaction, Task<T>> action,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        // The current schema has no unique key on name/role. Serialize account writes through the check and write.
        await RunAsync(connection, transaction, "LOCK TABLE public.users IN SHARE ROW EXCLUSIVE MODE;", null, cancellationToken);
        var result = await action(connection, transaction);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
}
