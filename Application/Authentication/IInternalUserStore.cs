using GerenciamentoMecanica.Autenticacao.Domain.Users;

namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public enum InternalUserUpdateResult { Updated, NotFound, Conflict }

public interface IInternalUserStore
{
    Task<InternalUser?> FindUserAsync(string name, string role, CancellationToken cancellationToken);
    Task<InternalUser?> FindUserByIdAsync(Guid id, CancellationToken cancellationToken);
    Task<bool> TryCreateAsync(InternalUser user, Func<string> hashPassword, CancellationToken cancellationToken);
    // Evaluate the password against the account as it will be after the update, under the write lock.
    Task<InternalUserUpdateResult> UpdateAsync(Guid id, string? name, Func<InternalUser, string>? hashPassword, CancellationToken cancellationToken);
    Task<bool> TryDeleteAsync(Guid id, CancellationToken cancellationToken);
}
