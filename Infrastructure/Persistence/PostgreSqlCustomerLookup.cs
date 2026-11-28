using GerenciamentoMecanica.Autenticacao.Infrastructure.Observability;
using Dapper;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using GerenciamentoMecanica.Autenticacao.Domain.Customers;
using Npgsql;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Persistence;

public sealed class PostgreSqlCustomerLookup(NpgsqlDataSource database, IntegrationMetrics? metrics = null) : ICustomerLookup
{
    private const string Query = """
                                 SELECT customer_id AS Id, name, document, status
                                 FROM public.customer_access
                                 WHERE document = @Document AND status <> 'Revoked';
                                 """;

    public async Task<CustomerIdentity?> FindByDocumentAsync(
        string canonicalDocument, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalDocument);
        cancellationToken.ThrowIfCancellationRequested();

        await using var connection = await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "connection.open", "application",
            () => database.OpenConnectionAsync(cancellationToken).AsTask(), cancellationToken);
        
        var command = new CommandDefinition(Query, new { Document = canonicalDocument },
            commandTimeout: 5, cancellationToken: cancellationToken);
        
        var row = await IntegrationMetrics.MeasureAsync(metrics, "postgresql", "command.execute", "application",
            () => connection.QuerySingleOrDefaultAsync<CustomerRow>(command), cancellationToken);

        return row?.ToIdentity();
    }
}
