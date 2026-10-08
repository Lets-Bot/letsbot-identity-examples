using System.Security.Claims;
using LetsBot.IdentityExample;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

// Placeholder authentication — replace with your own scheme (cookies, JWT bearer, Identity, ...).
builder.Services.AddAuthentication(DemoAuthHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, DemoAuthHandler>(DemoAuthHandler.SchemeName, null);
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/letsbot/identity-token", (ClaimsPrincipal user, IConfiguration config, HttpContext http) =>
{
    var secret = config["LETSBOT_IDENTITY_SECRET"] ?? string.Empty;
    var now = DateTimeOffset.UtcNow;
    var lifetime = LetsBotIdentityToken.DefaultLifetime; // 24 h recommended, 7 days max
    var token = LetsBotIdentityToken.Create(
        user.FindFirstValue(ClaimTypes.NameIdentifier)!, secret, lifetime,
        name: user.FindFirstValue(ClaimTypes.Name),
        email: user.FindFirstValue(ClaimTypes.Email),
        phone: user.FindFirstValue(ClaimTypes.MobilePhone),
        now: now);

    http.Response.Headers.CacheControl = "no-store";
    return Results.Json(new { token, expires_at = now.ToUnixTimeSeconds() + (long)lifetime.TotalSeconds });
}).RequireAuthorization();

app.Run();

/// <summary>Accepts <c>Authorization: Bearer demo-session</c> as user-42. Demo only.</summary>
public sealed class DemoAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Demo";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Headers.Authorization.ToString() != "Bearer demo-session")
            return Task.FromResult(AuthenticateResult.NoResult());

        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "user-42"),
            new Claim(ClaimTypes.Name, "Sara"),
            new Claim(ClaimTypes.Email, "sara@example.com"),
            new Claim(ClaimTypes.MobilePhone, "+966501234567"),
        }, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

public partial class Program;
