using GerenciamentoMecanica.Auth.Contracts;
using GerenciamentoMecanica.Autenticacao.Infrastructure.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace GerenciamentoMecanica.Autenticacao.Infrastructure.Authentication;

public sealed class InternalUserTokenValidator(JwtConfiguration jwt)
{
    private readonly JwtSecurityTokenHandler handler = new() { MapInboundClaims = true };
    private readonly TokenValidationParameters validation = new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
        ValidAlgorithms = [JwtIssuer.Algorithm],
        ClockSkew = TimeSpan.Zero
    };

    public ClaimsPrincipal? Validate(string token)
    {
        try { return handler.ValidateToken(token, validation, out _); }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException) { return null; }
    }
}
