using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Helpers;

public static class IdentityExtensions
{
    public static Guid GetUserId(this ClaimsPrincipal principal)
    {
        var userIdStr = principal.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
        return Guid.Parse(userIdStr);
    }

    private static readonly JwtSecurityTokenHandler JwtSecurityTokenHandler = new JwtSecurityTokenHandler();

    public static string GenerateJwtToken(
        IEnumerable<Claim> claims,
        string key,
        string issuer,
        string audience,
        DateTime expiration)
    {
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expiration,
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static bool ValidateToken(string jwt, string key, string issuer, string audience)
    {
        var validationParams = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidateIssuer = true,
            ValidAudience = audience,
            ValidateAudience = true,

            ValidateLifetime = false,
            RoleClaimType = ClaimTypes.Role
        };

        try
        {
            new JwtSecurityTokenHandler().ValidateToken(jwt, validationParams, out _);
        }
        catch (Exception)
        {
            return false;
        }

        return true;
    }
}