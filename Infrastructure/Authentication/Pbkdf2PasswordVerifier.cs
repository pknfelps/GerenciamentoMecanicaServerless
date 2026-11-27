using System.Security.Cryptography;
using GerenciamentoMecanica.Autenticacao.Application.Authentication;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Authentication;

public sealed class Pbkdf2PasswordVerifier : IInternalPasswordVerifier
{
    private const string Algorithm = "pbkdf2-sha256";
    private const int Iterations = 100_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public bool Verify(string password, string? passwordHash)
    {
        Span<byte> salt = stackalloc byte[SaltSize];
        Span<byte> expected = stackalloc byte[HashSize];
        salt.Clear();
        expected.Clear();

        var parts = passwordHash?.Split('$');
        var compatible = parts is { Length: 4 }
            && parts[0] == Algorithm
            && int.TryParse(parts[1], out var iterations) && iterations == Iterations
            && Convert.TryFromBase64String(parts[2], salt, out var saltSize) && saltSize == SaltSize
            && Convert.TryFromBase64String(parts[3], expected, out var hashSize) && hashSize == HashSize;

        // A missing or invalid credential still incurs the same derivation as a wrong password.
        Span<byte> actual = stackalloc byte[HashSize];
        Rfc2898DeriveBytes.Pbkdf2(password.AsSpan(), salt, actual, Iterations, HashAlgorithmName.SHA256);
        return CryptographicOperations.FixedTimeEquals(actual, expected) && compatible;
    }
}
