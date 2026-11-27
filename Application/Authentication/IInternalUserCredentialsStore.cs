namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public interface IInternalUserCredentialsStore
{
    Task<InternalUserCredentials?> FindAsync(string name, string role, CancellationToken cancellationToken);
}
