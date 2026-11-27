using System.Net.Mail;
using System.Security.Cryptography;
using Dapper;
using GerenciamentoMecanica.Auth.Contracts;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Domain.Customers;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Authentication;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Observability;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Persistence;

public sealed class PostgreSqlCustomerAccessStore(
    NpgsqlDataSource database, ILogger<PostgreSqlCustomerAccessStore> logger,
    IntegrationMetrics? metrics = null, Func<string>? generateCode = null) : ICustomerAccessStore
{
    private const int CleanupBatchSize = 100;
    private const string CustomerColumns = "customer_id AS Id, name, document, status, email";
    private const string ChallengeColumns = """
        id, customer_id AS CustomerId, code_salt AS Salt, code_verifier AS Verifier,
        created_at AS CreatedAt, expires_at AS ExpiresAt, state, failed_attempts AS FailedAttempts,
        consumed_at AS ConsumedAt, invalidated_at AS InvalidatedAt
        """;

    public async Task<CustomerAccessWriteOutcome> SynchronizeAsync(
        CustomerAccessSyncCommand command, CancellationToken cancellationToken)
    {
        if (!command.IsValid())
            return CustomerAccessWriteOutcome.Rejected;
        if (command.Access is { } input)
        {
            try
            {
                if (DocumentRules.Normalize(input.Document) != input.Document)
                    return CustomerAccessWriteOutcome.Rejected;
            }
            catch (FormatException) { return CustomerAccessWriteOutcome.Rejected; }
        }

        await using var connection = await OpenAsync(cancellationToken);
        try
        {
            return await InCustomerTransactionAsync(connection, command.CustomerId, async transaction =>
            {
                var current = await ReadAsync<AccessRevision>(connection, transaction, """
                    SELECT revision, name, document, email, status FROM public.customer_access WHERE customer_id = @CustomerId;
                    """, new { command.CustomerId }, cancellationToken);
                var access = command.Access;
                var status = access?.Status ?? "Revoked";
                if (current is not null)
                {
                    if (current.Revision > command.Revision)
                        return CustomerAccessWriteOutcome.Stale;
                    if (current.Revision == command.Revision)
                        return current.Name == access?.Name && current.Document == access?.Document
                            && current.Email == access?.Email && current.Status == status
                            ? CustomerAccessWriteOutcome.Applied
                            : CustomerAccessWriteOutcome.Rejected;
                    if (current.Status == "Revoked" && access is not null)
                        return CustomerAccessWriteOutcome.Rejected;
                }

                await ExecuteAsync(connection, transaction, """
                    INSERT INTO public.customer_access(customer_id, name, document, email, status, revision)
                    VALUES (@CustomerId, @Name, @Document, @Email, @Status, @Revision)
                    ON CONFLICT (customer_id) DO UPDATE SET
                        name = EXCLUDED.name, document = EXCLUDED.document, email = EXCLUDED.email,
                        status = EXCLUDED.status, revision = EXCLUDED.revision;
                    """, new { command.CustomerId, command.Revision, Name = access?.Name, Document = access?.Document,
                        Email = access?.Email, Status = status },
                    cancellationToken);

                if (status == "Revoked" || current is not null &&
                    (current.Email != access?.Email || (status == "Inactive" && current.Status != status)))
                {
                    await ExecuteAsync(connection, transaction, """
                        UPDATE public.customer_auth_challenges SET state = 'Invalidated', invalidated_at = clock_timestamp()
                        WHERE customer_id = @CustomerId AND state IN ('Pending', 'Ready');
                        """, new { command.CustomerId }, cancellationToken);
                }

                return CustomerAccessWriteOutcome.Applied;
            }, cancellationToken);
        }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.UniqueViolation
            && error.ConstraintName == "customer_access_document_key")
        {
            return CustomerAccessWriteOutcome.DocumentConflict;
        }
    }

    private sealed class AccessRevision
    {
        public long Revision { get; set; }
        public string? Name { get; set; }
        public string? Document { get; set; }
        public string? Email { get; set; }
        public string? Status { get; set; }
    }

    public async Task<CustomerCodeRequestResult> CreatePendingAsync(string canonicalDocument,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalDocument);
        await using var connection = await OpenAsync(cancellationToken);
        var customer = await ReadAsync<CustomerRow>(connection, null,
            $"SELECT {CustomerColumns} FROM public.customer_access WHERE document = @Document AND status <> 'Revoked'",
            new { Document = canonicalDocument }, cancellationToken);

        // No transaction, code generation, cleanup or write for an unknown customer.
        if (customer is null)
            return MissingCustomer();
        if (!Eligible(customer))
            return CustomerCodeRequestResult.NotEligible();

        var result = await InCustomerTransactionAsync(connection, customer.Id, async transaction =>
        {
            customer = await FindCustomerAsync(connection, transaction, customer.Id, cancellationToken);
            if (customer is null)
                return MissingCustomer();
            if (!Eligible(customer) || customer.Document != canonicalDocument)
                return CustomerCodeRequestResult.NotEligible();

            var now = await NowAsync(connection, transaction, cancellationToken);
            var existingLimit = await ReadAsync<AccessRequestLimitRow>(connection, transaction, """
                SELECT window_started_at AS WindowStartedAt, window_expires_at AS WindowExpiresAt,
                    request_count AS RequestCount, last_requested_at AS LastRequestedAt
                FROM public.customer_auth_request_limits WHERE customer_id = @CustomerId FOR UPDATE
                """, new { CustomerId = customer.Id }, cancellationToken);
            var limit = existingLimit?.ToDomain() ?? CustomerAccessRequestLimit.FirstRequest(now);
            if (existingLimit is not null && !limit.TryAdmit(now, out var retryAfterSeconds))
                return CustomerCodeRequestResult.RateLimited(retryAfterSeconds);

            var code = (generateCode ?? CustomerAccessCode.Generate)();
            if (!CustomerAccessCode.IsWellFormed(code))
                throw new InvalidOperationException("Generated access code is invalid.");
            var salt = RandomNumberGenerator.GetBytes(16);
            var verifier = CustomerAccessCode.Derive(code, salt);
            cancellationToken.ThrowIfCancellationRequested();
            var challenge = new CustomerAccessChallenge(Guid.NewGuid(), customer.Id, salt, verifier,
                now, now.AddMinutes(5), CustomerAccessChallengeState.Pending);

            var previous = await QueryAsync<AccessChallengeRow>(connection, transaction,
                $"SELECT {ChallengeColumns} FROM public.customer_auth_challenges " +
                "WHERE customer_id = @CustomerId AND state IN ('Pending', 'Ready') ORDER BY id FOR UPDATE",
                new { CustomerId = customer.Id }, cancellationToken);
            // Validate all rows in C# before any writes. Invalid stored data is technical.
            var openChallenges = previous.Select(row => row.ToDomain()).ToArray();
            await SaveLimitAsync(connection, transaction, customer.Id, limit, existingLimit is null, cancellationToken);
            foreach (var oldChallenge in openChallenges)
                await InvalidateChallengeAsync(connection, transaction, oldChallenge, now, cancellationToken);

            await ExecuteAsync(connection, transaction, """
                INSERT INTO public.customer_auth_challenges
                    (id, customer_id, code_salt, code_verifier, created_at, expires_at, state, failed_attempts)
                VALUES (@Id, @CustomerId, @Salt, @Verifier, @CreatedAt, @ExpiresAt, @State, @FailedAttempts)
                """, new { challenge.Id, challenge.CustomerId, challenge.Salt, challenge.Verifier,
                    challenge.CreatedAt, challenge.ExpiresAt, State = challenge.State.ToString(), challenge.FailedAttempts }, cancellationToken);
            return CustomerCodeRequestResult.Pending(challenge.Id, customer.ToIdentity(), customer.Email!, code);
        }, cancellationToken);
        // The admitted request is already committed; cleanup cannot undo it.
        if (result.Outcome == CustomerCodeRequestOutcome.Pending)
            await CleanupExpiredAsync(connection, cancellationToken);
        return result;
    }

    public async Task<bool> ActivateAsync(Guid customerId, Guid challengeId, CancellationToken cancellationToken = default)
    {
        RequireIds(customerId, challengeId);
        await using var connection = await OpenAsync(cancellationToken);
        return await InCustomerTransactionAsync(connection, customerId, async transaction =>
        {
            var challenge = await FindChallengeAsync(connection, transaction, customerId, challengeId, cancellationToken);
            if (challenge is null || challenge.State != CustomerAccessChallengeState.Pending)
                return false;
            var customer = await FindCustomerAsync(connection, transaction, customerId, cancellationToken);
            var now = await NowAsync(connection, transaction, cancellationToken);
            if (customer is null || !Eligible(customer) || now >= challenge.ExpiresAt)
            {
                await InvalidateChallengeAsync(connection, transaction, challenge, now, cancellationToken);
                return false;
            }
            var previousState = challenge.State;
            var previousAttempts = challenge.FailedAttempts;
            if (!challenge.Activate(now))
                return false;
            await SaveChallengeAsync(connection, transaction, challenge, previousState, previousAttempts, cancellationToken);
            return true;
        }, cancellationToken);
    }

    public async Task<bool> InvalidateAsync(Guid customerId, Guid challengeId, CancellationToken cancellationToken = default)
    {
        RequireIds(customerId, challengeId);
        await using var connection = await OpenAsync(cancellationToken);
        return await InCustomerTransactionAsync(connection, customerId, async transaction =>
        {
            var challenge = await FindChallengeAsync(connection, transaction, customerId, challengeId, cancellationToken);
            if (challenge is null || !challenge.IsOpen)
                return false;
            var now = await NowAsync(connection, transaction, cancellationToken);
            await InvalidateChallengeAsync(connection, transaction, challenge, now, cancellationToken);
            return true;
        }, cancellationToken);
    }

    public async Task<CustomerAuthenticationResult> VerifyAndConsumeAsync(Guid challengeId, string canonicalDocument,
        string code, ICustomerTokenIssuer tokenIssuer, CancellationToken cancellationToken = default)
    {
        if (challengeId == Guid.Empty || !CustomerAccessCode.IsWellFormed(code))
            throw new ArgumentException("Challenge identifier and eight-digit code are required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalDocument);
        ArgumentNullException.ThrowIfNull(tokenIssuer);
        await using var connection = await OpenAsync(cancellationToken);
        var customerId = await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleOrDefaultAsync<Guid?>(Command(
                "SELECT customer_id FROM public.customer_auth_challenges WHERE id = @Id", new { Id = challengeId }, null, cancellationToken)), cancellationToken);
        if (customerId is null)
            return CustomerAuthenticationResult.NotEligible();
        if (customerId == Guid.Empty)
            throw new InvalidDataException("Stored challenge customer identifier is invalid.");

        return await InCustomerTransactionAsync(connection, customerId.Value, async transaction =>
        {
            var challenge = await FindChallengeAsync(connection, transaction, customerId.Value, challengeId, cancellationToken);
            if (challenge is null || !challenge.IsOpen)
                return CustomerAuthenticationResult.NotEligible();
            var customer = await FindCustomerAsync(connection, transaction, customerId.Value, cancellationToken);
            var now = await NowAsync(connection, transaction, cancellationToken);
            if (customer is null || !customer.ToIdentity().IsEligible || now >= challenge.ExpiresAt)
            {
                await InvalidateChallengeAsync(connection, transaction, challenge, now, cancellationToken);
                return CustomerAuthenticationResult.NotEligible();
            }
            if (!challenge.CanVerify(now))
                return CustomerAuthenticationResult.NotEligible();

            var matches = customer.Document == canonicalDocument
                && CustomerAccessCode.Matches(code, challenge.Salt, challenge.Verifier);
            cancellationToken.ThrowIfCancellationRequested();
            now = await NowAsync(connection, transaction, cancellationToken);
            if (!challenge.CanVerify(now))
            {
                await InvalidateChallengeAsync(connection, transaction, challenge, now, cancellationToken);
                return CustomerAuthenticationResult.NotEligible();
            }
            var previousState = challenge.State;
            var previousAttempts = challenge.FailedAttempts;
            if (!matches)
            {
                challenge.RejectAttempt(now);
                await SaveChallengeAsync(connection, transaction, challenge, previousState, previousAttempts, cancellationToken);
                // A negative result must COMMIT the failed attempt, never throw a business error.
                return CustomerAuthenticationResult.NotEligible();
            }

            // Prepare signing before consuming; return the result only after the transaction commits.
            var token = tokenIssuer.Generate(customer.ToIdentity());
            ArgumentException.ThrowIfNullOrWhiteSpace(token);
            cancellationToken.ThrowIfCancellationRequested();
            now = await NowAsync(connection, transaction, cancellationToken);
            if (!challenge.CanVerify(now))
            {
                await InvalidateChallengeAsync(connection, transaction, challenge, now, cancellationToken);
                return CustomerAuthenticationResult.NotEligible();
            }
            challenge.Consume(now);
            await SaveChallengeAsync(connection, transaction, challenge, previousState, previousAttempts, cancellationToken);
            return CustomerAuthenticationResult.Authenticated(token);
        }, cancellationToken);
    }

    private CustomerCodeRequestResult MissingCustomer()
    {
        logger.LogInformation("Solicitação de autenticação para cliente não encontrado.");
        return CustomerCodeRequestResult.CustomerNotFound();
    }

    private static bool Eligible(CustomerRow row) => row.ToIdentity().IsEligible
        && MailAddress.TryCreate(row.Email, out var address) && address.Address == row.Email;

    private Task<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken) =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "connection.open", "application",
            () => database.OpenConnectionAsync(cancellationToken).AsTask(), cancellationToken);

    private async Task CleanupExpiredAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
            return;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(1));
        try
        {
            await InTransactionAsync(connection, async transaction =>
            {
                var now = await NowAsync(connection, transaction, budget.Token);
                await ExecuteAsync(connection, transaction, """
                    WITH expired AS (
                        SELECT id FROM public.customer_auth_challenges
                        WHERE expires_at <= @Now
                        ORDER BY expires_at, id LIMIT @BatchSize FOR UPDATE SKIP LOCKED
                    )
                    DELETE FROM public.customer_auth_challenges AS challenge
                    USING expired WHERE challenge.id = expired.id
                    """, new { Now = now, BatchSize = CleanupBatchSize }, budget.Token);
                await ExecuteAsync(connection, transaction, """
                    WITH expired AS (
                        SELECT customer_id FROM public.customer_auth_request_limits
                        WHERE window_expires_at <= @Now AND last_requested_at <= @CooldownEndedBefore
                        ORDER BY window_expires_at, customer_id LIMIT @BatchSize FOR UPDATE SKIP LOCKED
                    )
                    DELETE FROM public.customer_auth_request_limits AS request_limit
                    USING expired WHERE request_limit.customer_id = expired.customer_id
                    """, new { Now = now, CooldownEndedBefore = now.AddSeconds(-60), BatchSize = CleanupBatchSize }, budget.Token);
                return true;
            }, budget.Token);
        }
        catch (Exception error)
        {
            logger.LogWarning("Não foi possível limpar os registros expirados de autenticação. Tipo: {ExceptionType}",
                error.GetType().FullName);
        }
    }

    private Task<T> InCustomerTransactionAsync<T>(NpgsqlConnection connection, Guid customerId,
        Func<NpgsqlTransaction, Task<T>> action, CancellationToken cancellationToken) =>
        InTransactionAsync(connection, async transaction =>
        {
            await ExecuteAsync(connection, transaction,
                "SELECT pg_advisory_xact_lock(hashtextextended(CAST(@CustomerId AS text), 0))",
                new { CustomerId = customerId }, cancellationToken);
            return await action(transaction);
        }, cancellationToken);

    private async Task<T> InTransactionAsync<T>(NpgsqlConnection connection,
        Func<NpgsqlTransaction, Task<T>> action, CancellationToken cancellationToken)
    {
        await using var transaction = await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "transaction.begin", "application",
            () => connection.BeginTransactionAsync(cancellationToken).AsTask(), cancellationToken);
        try
        {
            var result = await action(transaction);
            await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "transaction.commit", "application",
                async () => { await transaction.CommitAsync(cancellationToken); return true; }, cancellationToken);
            return result;
        }
        catch
        {
            try
            {
                using var rollbackBudget = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "transaction.rollback", "application",
                    async () => { await transaction.RollbackAsync(rollbackBudget.Token); return true; }, cancellationToken);
            }
            catch (Exception error)
            {
                logger.LogError("Não foi possível reverter a transação de autenticação. Tipo: {ExceptionType}", error.GetType().FullName);
            }
            throw;
        }
    }

    private Task<CustomerRow?> FindCustomerAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid id, CancellationToken cancellationToken) => ReadAsync<CustomerRow>(connection, transaction,
        $"SELECT {CustomerColumns} FROM public.customer_access WHERE customer_id = @Id AND status <> 'Revoked'",
        new { Id = id }, cancellationToken);

    private async Task<CustomerAccessChallenge?> FindChallengeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid customerId, Guid id, CancellationToken cancellationToken)
    {
        var row = await ReadAsync<AccessChallengeRow>(connection, transaction,
            $"SELECT {ChallengeColumns} FROM public.customer_auth_challenges WHERE id = @Id AND customer_id = @CustomerId FOR UPDATE",
            new { Id = id, CustomerId = customerId }, cancellationToken);
        return row?.ToDomain();
    }

    private async Task InvalidateChallengeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CustomerAccessChallenge challenge, DateTime now, CancellationToken cancellationToken)
    {
        var previousState = challenge.State;
        var previousAttempts = challenge.FailedAttempts;
        if (challenge.Invalidate(now))
            await SaveChallengeAsync(connection, transaction, challenge, previousState, previousAttempts, cancellationToken);
    }

    private async Task SaveChallengeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CustomerAccessChallenge challenge, CustomerAccessChallengeState previousState, int previousAttempts,
        CancellationToken cancellationToken)
    {
        var changed = await ExecuteAsync(connection, transaction, """
            UPDATE public.customer_auth_challenges
            SET state = @State, failed_attempts = @FailedAttempts, consumed_at = @ConsumedAt, invalidated_at = @InvalidatedAt
            WHERE id = @Id AND customer_id = @CustomerId AND state = @PreviousState AND failed_attempts = @PreviousAttempts
            """, new { challenge.Id, challenge.CustomerId, State = challenge.State.ToString(), challenge.FailedAttempts,
                challenge.ConsumedAt, challenge.InvalidatedAt, PreviousState = previousState.ToString(), PreviousAttempts = previousAttempts }, cancellationToken);
        if (changed != 1)
            throw new InvalidOperationException("Challenge update was not confirmed.");
    }

    private async Task SaveLimitAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid customerId,
        CustomerAccessRequestLimit limit, bool insert, CancellationToken cancellationToken)
    {
        var sql = insert ? """
            INSERT INTO public.customer_auth_request_limits
                (customer_id, window_started_at, window_expires_at, request_count, last_requested_at)
            VALUES (@CustomerId, @WindowStartedAt, @WindowExpiresAt, @RequestCount, @LastRequestedAt)
            """ : """
            UPDATE public.customer_auth_request_limits
            SET window_started_at = @WindowStartedAt, window_expires_at = @WindowExpiresAt,
                request_count = @RequestCount, last_requested_at = @LastRequestedAt
            WHERE customer_id = @CustomerId
            """;
        var changed = await ExecuteAsync(connection, transaction, sql,
            new { CustomerId = customerId, limit.WindowStartedAt, limit.WindowExpiresAt, limit.RequestCount, limit.LastRequestedAt }, cancellationToken);
        if (changed != 1)
            throw new InvalidOperationException("Customer request limit update was not confirmed.");
    }

    private Task<T?> ReadAsync<T>(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql,
        object parameters, CancellationToken cancellationToken) where T : class =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleOrDefaultAsync<T>(Command(sql, parameters, transaction, cancellationToken)), cancellationToken);

    private Task<IEnumerable<T>> QueryAsync<T>(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        object parameters, CancellationToken cancellationToken) =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QueryAsync<T>(Command(sql, parameters, transaction, cancellationToken)), cancellationToken);

    private Task<int> ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        object parameters, CancellationToken cancellationToken) =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.ExecuteAsync(Command(sql, parameters, transaction, cancellationToken)), cancellationToken);

    private Task<DateTime> NowAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken) =>
        IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleAsync<DateTime>(Command("SELECT clock_timestamp()", null, transaction, cancellationToken)), cancellationToken);

    private static CommandDefinition Command(string sql, object? parameters, NpgsqlTransaction? transaction,
        CancellationToken cancellationToken) => new(sql, parameters, transaction, commandTimeout: 5, cancellationToken: cancellationToken);

    private static void RequireIds(Guid customerId, Guid challengeId)
    {
        if (customerId == Guid.Empty || challengeId == Guid.Empty)
            throw new ArgumentException("Customer and challenge identifiers are required.");
    }
}
