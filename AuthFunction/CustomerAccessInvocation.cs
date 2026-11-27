using Amazon.Lambda.Core;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GerenciamentoMecanica.Autenticacao.Function;

internal static class CustomerAccessInvocation
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.Strict,
        AllowDuplicateProperties = false
    };

    public static async Task<object> HandleAsync(JsonElement input, ILambdaContext context, FunctionRuntimeProvider? runtime)
    {
        CustomerAccessSyncCommand? command;
        try { command = input.Deserialize<CustomerAccessSyncCommand>(JsonOptions); }
        catch (JsonException) { return Reply(null, "rejected"); }
        if (command is null || !command.IsValid())
            return Reply(command, "rejected");

        var budget = context.RemainingTime - TimeSpan.FromSeconds(1);
        if (budget <= TimeSpan.Zero || runtime is null)
            return Reply(command, "pending");
        using var cancellation = new CancellationTokenSource(budget);
        try
        {
            var execution = await runtime.GetRuntimeAsync(cancellation.Token).WaitAsync(cancellation.Token);
            var outcome = await execution.CustomerAccess.SynchronizeAsync(command, cancellation.Token).WaitAsync(cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            return Reply(command, outcome switch
            {
                CustomerAccessWriteOutcome.Applied => "applied",
                CustomerAccessWriteOutcome.Stale => "stale",
                CustomerAccessWriteOutcome.DocumentConflict => "document-conflict",
                _ => "rejected"
            });
        }
        catch (Exception error)
        {
            context.Logger.LogLine(JsonSerializer.Serialize(new { operation = CustomerAccessSyncCommand.SyncOperation, exceptionType = error.GetType().Name }));
            return Reply(command, "pending");
        }
    }

    private static object Reply(CustomerAccessSyncCommand? command, string outcome) => new
    {
        version = CustomerAccessSyncCommand.ContractVersion,
        customerId = command?.CustomerId ?? Guid.Empty,
        revision = command?.Revision ?? 0,
        outcome
    };
}
