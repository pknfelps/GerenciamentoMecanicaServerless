using System.Text.Json.Serialization;

namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CustomerAccessSyncCommand
{
    public const string SyncOperation = "sync-customer-access";
    public const int ContractVersion = 1;

    public string? Operation { get; init; }
    public int Version { get; init; }
    public Guid CustomerId { get; init; }
    public long Revision { get; init; }
    public string? Action { get; init; }
    public CustomerAccessSyncData? Access { get; init; }

    public bool IsValid()
    {
        if (Operation != SyncOperation || Version != ContractVersion || CustomerId == Guid.Empty || Revision < 1)
            return false;
        if (Action == "revoke")
            return Access is null;
        if (Action != "upsert" || Access is null || string.IsNullOrWhiteSpace(Access.Name) || Access.Name.Length > 100
            || string.IsNullOrWhiteSpace(Access.Email) || Access.Email.Length > 100 || Access.Email.Contains(' ')
            || !Access.Email.Contains('@') || Access.Status is not ("Active" or "Inactive"))
            return false;
        return !string.IsNullOrWhiteSpace(Access.Document);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CustomerAccessSyncData
{
    public string? Name { get; init; }
    public string? Document { get; init; }
    public string? Email { get; init; }
    public string? Status { get; init; }
}

public enum CustomerAccessWriteOutcome { Applied, Stale, Rejected, DocumentConflict }
