namespace GerenciamentoMecanica.Autenticacao.Domain.Users;

public static class InternalUserPasswordRules
{
    public static string? ValidationError(string password, InternalUser user)
    {
        if (string.IsNullOrWhiteSpace(password))
            return "Senha deve ser preenchida";
        if (password.Any(char.IsWhiteSpace))
            return "Senha não deve conter espaços em branco";
        if (password.Length < 6)
            return "Senha deve conter pelo menos 6 caracteres";
        if (!password.Any(char.IsLetter) || !password.Any(char.IsDigit)
            || !password.Any(character => char.IsSymbol(character) || char.IsPunctuation(character)))
            return "Senha deve conter letras, números e símbolos";
        if (!password.Any(char.IsUpper) || !password.Any(char.IsLower))
            return "Senha deve conter letras maiúsculas e minúsculas";
        return password == user.Name || password == user.Role
            ? "Senha deve ser diferente do nome e do cargo"
            : null;
    }
}
