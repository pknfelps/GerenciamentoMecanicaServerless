namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public interface IInternalPasswordVerifier
{
    bool Verify(string password, string? passwordHash);
}
