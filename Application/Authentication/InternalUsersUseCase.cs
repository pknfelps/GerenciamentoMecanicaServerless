using GerenciamentoMecanica.Autenticacao.Domain.Users;

namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public sealed class InternalUsersUseCase(IInternalUserStore store, IInternalPasswordHasher passwords)
{
    public async Task RegisterAsync(string name, string role, string password, CancellationToken cancellationToken)
    {
        if (!InternalUserRoles.IsValid(role))
            throw new InternalUserException(InternalUserFailure.InvalidInput, "Cargo inválido: informe Admin ou Mechanic");
        if (string.IsNullOrWhiteSpace(name))
            throw new InternalUserException(InternalUserFailure.InvalidInput, "Nome deve ser preenchido");

        var user = new InternalUser(Guid.NewGuid(), name, role);
        if (!await store.TryCreateAsync(user, () => Hash(password, user), cancellationToken))
            throw new InternalUserException(InternalUserFailure.Conflict, "Usuário já cadastrado no sistema");
    }

    public Task<InternalUser?> FindAsync(string name, string role, CancellationToken cancellationToken) =>
        store.FindUserAsync(name, role, cancellationToken);

    public async Task<InternalUser?> FindOwnAsync(Guid id, string name, string role, CancellationToken cancellationToken)
    {
        ValidateId(id);
        var user = await store.FindUserByIdAsync(id, cancellationToken);
        if (user is not null && ((name.Length > 0 && name != user.Name) || (role.Length > 0 && role != user.Role)))
            throw new InternalUserException(InternalUserFailure.AccessDenied, "A consulta deve se limitar à própria conta");
        return user;
    }

    public async Task UpdateOwnAsync(Guid id, string? name, string? password, CancellationToken cancellationToken)
    {
        ValidateId(id);
        if (name is null && password is null)
            throw new InternalUserException(InternalUserFailure.InvalidInput, "Informe nome ou senha para atualizar a conta");
        if (name is not null && (string.IsNullOrWhiteSpace(name) || name.Length > 100))
            throw new InternalUserException(InternalUserFailure.InvalidInput, "O nome deve ser preenchido e ter no máximo 100 caracteres");

        var result = await store.UpdateAsync(id, name, password is null ? null : user => Hash(password, user), cancellationToken);
        if (result == InternalUserUpdateResult.Conflict)
            throw new InternalUserException(InternalUserFailure.Conflict, "Nome já utilizado por outro usuário deste perfil");
        if (result == InternalUserUpdateResult.NotFound)
            throw new InternalUserException(InternalUserFailure.NotFound, "Usuário não encontrado");
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        ValidateId(id);
        if (!await store.TryDeleteAsync(id, cancellationToken))
            throw new InternalUserException(InternalUserFailure.NotFound, "Usuário não encontrado");
    }

    private string Hash(string password, InternalUser user)
    {
        if (InternalUserPasswordRules.ValidationError(password, user) is { } error)
            throw new InternalUserException(InternalUserFailure.InvalidInput, error);
        return passwords.Hash(password);
    }

    private static void ValidateId(Guid id)
    {
        if (id == Guid.Empty)
            throw new InternalUserException(InternalUserFailure.InvalidInput, "A identificação do usuário deve ser informada");
    }
}
