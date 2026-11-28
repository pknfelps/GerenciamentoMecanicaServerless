namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public sealed class InternalUserCredentials(Guid id, string name, string role, string passwordHash)
{
    public Guid Id { get; } = id;
    public string Name { get; } = name;
    public string Role { get; } = role;
    public string PasswordHash { get; } = passwordHash;
}
