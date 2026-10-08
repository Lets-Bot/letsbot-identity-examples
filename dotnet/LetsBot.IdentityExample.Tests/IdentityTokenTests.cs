using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LetsBot.IdentityExample;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace LetsBot.IdentityExample.Tests;

public class IdentityTokenTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Secret = "letsbot-test-identity-secret-0123456789";

    private static byte[] FromBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    /// <summary>Independent HS256 check with HMACSHA256 (no JWT library). Returns the claims.</summary>
    private static JsonElement VerifyHs256(string token, string secret)
    {
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.Equal("HS256", JsonDocument.Parse(FromBase64Url(parts[0])).RootElement.GetProperty("alg").GetString());
        var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"));
        Assert.True(CryptographicOperations.FixedTimeEquals(expected, FromBase64Url(parts[2])), "signature must verify");
        return JsonDocument.Parse(FromBase64Url(parts[1])).RootElement;
    }

    [Fact]
    public void TokenVerifiesWithSubIatExp()
    {
        var token = LetsBotIdentityToken.Create("42", Secret, now: DateTimeOffset.FromUnixTimeSeconds(1791446400), phone: "");
        var claims = VerifyHs256(token, Secret);
        Assert.Equal("42", claims.GetProperty("sub").GetString());
        Assert.Equal(1791446400, claims.GetProperty("iat").GetInt64());
        Assert.Equal(1791446400 + 86400, claims.GetProperty("exp").GetInt64());
        Assert.False(claims.TryGetProperty("phone", out _));
        Assert.Throws<Xunit.Sdk.TrueException>(() => VerifyHs256(token, Secret + "x"));
    }

    [Fact]
    public void RejectsBadInput()
    {
        Assert.Throws<ArgumentException>(() => LetsBotIdentityToken.Create("u", ""));
        Assert.Throws<ArgumentException>(() => LetsBotIdentityToken.Create(" ", Secret));
        Assert.Throws<ArgumentException>(() => LetsBotIdentityToken.Create(new string('x', 192), Secret));
        Assert.Throws<ArgumentOutOfRangeException>(() => LetsBotIdentityToken.Create("u", Secret, TimeSpan.FromDays(8)));
    }

    [Fact]
    public async Task Endpoint()
    {
        var client = factory.WithWebHostBuilder(b => b.UseSetting("LETSBOT_IDENTITY_SECRET", Secret)).CreateClient();

        var anonymous = await client.GetAsync("/api/letsbot/identity-token");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/letsbot/identity-token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "demo-session");
        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        var claims = VerifyHs256(body.GetProperty("token").GetString()!, Secret);
        Assert.Equal("user-42", claims.GetProperty("sub").GetString());
        Assert.Equal("sara@example.com", claims.GetProperty("email").GetString());
        Assert.Equal(86400, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
        Assert.Equal(claims.GetProperty("exp").GetInt64(), body.GetProperty("expires_at").GetInt64());
    }
}
