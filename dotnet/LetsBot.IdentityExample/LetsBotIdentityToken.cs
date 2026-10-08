using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace LetsBot.IdentityExample;

/// <summary>
/// LetsBot In-App Chat identity token: JWT, HS256, signed with the app's Identity Secret.
/// Claims: sub, iat, exp (+ optional name, email, phone).
/// </summary>
public static class LetsBotIdentityToken
{
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(24);
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(7);

    public static string Create(string userId, string secret, TimeSpan? lifetime = null,
        string? name = null, string? email = null, string? phone = null, DateTimeOffset? now = null)
    {
        if (string.IsNullOrEmpty(secret)) throw new ArgumentException("Identity Secret is missing", nameof(secret));
        var sub = (userId ?? string.Empty).Trim();
        if (sub.Length == 0 || sub.EnumerateRunes().Count() > 191)
            throw new ArgumentException("userId must be 1-191 characters", nameof(userId));
        var ttl = lifetime ?? DefaultLifetime;
        if (ttl < TimeSpan.FromSeconds(1) || ttl > MaxLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "lifetime must be between 1 second and 7 days");

        var iat = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var payload = new JwtPayload
        {
            { "sub", sub },
            { "iat", iat },
            { "exp", iat + (long)ttl.TotalSeconds },
        };
        if (!string.IsNullOrEmpty(name)) payload["name"] = name;
        if (!string.IsNullOrEmpty(email)) payload["email"] = email;
        if (!string.IsNullOrEmpty(phone)) payload["phone"] = phone;

        // This library refuses HS256 keys shorter than 32 bytes (256 bits).
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var header = new JwtHeader(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }
}
