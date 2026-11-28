namespace GerenciamentoMecanica.Autenticacao.Domain.Users;

public static class InternalUserRoles
{
    public static bool IsValid(string? role) => role is "Admin" or "Mechanic";
}
