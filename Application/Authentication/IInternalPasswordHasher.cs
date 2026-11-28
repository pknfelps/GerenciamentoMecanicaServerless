namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public interface IInternalPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string? passwordHash);
}
