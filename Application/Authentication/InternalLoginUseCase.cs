using GerenciamentoMecanica.Autenticacao.Domain.Users;

namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public sealed class InternalLoginUseCase(
    IInternalUserCredentialsStore store,
    IInternalPasswordHasher passwordHasher,
    Func<string, string, Guid, string> issueToken)
{
    public async Task<string?> ExecuteAsync(string name, string password, string role, CancellationToken cancellationToken)
    {
        if (!InternalUserRoles.IsValid(role))
            return null;

        var credentials = await store.FindAsync(name, role, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var validPassword = passwordHasher.Verify(password, credentials?.PasswordHash);
        cancellationToken.ThrowIfCancellationRequested();

        return validPassword && credentials is not null && credentials.Role == role
            ? issueToken(credentials.Name, credentials.Role, credentials.Id)
            : null;
    }
}
