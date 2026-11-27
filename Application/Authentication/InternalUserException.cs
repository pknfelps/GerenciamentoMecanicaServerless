namespace GerenciamentoMecanica.Autenticacao.Application.Authentication;

public enum InternalUserFailure { InvalidInput, AccessDenied, NotFound, Conflict }

public sealed class InternalUserException(InternalUserFailure failure, string message) : Exception(message)
{
    public InternalUserFailure Failure { get; } = failure;
}
