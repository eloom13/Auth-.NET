using Auth.Models.DTOs;
using Auth.Services.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Auth.API.Middleware
{
    /// <summary>
    /// Middleware za automatsko osvježavanje JWT tokena kada istekne
    /// </summary>
    public class JwtAutoRefreshMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtAutoRefreshMiddleware> _logger;

        public JwtAutoRefreshMiddleware(RequestDelegate next, ILogger<JwtAutoRefreshMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context, IAuthService authService, IOptions<Auth.Services.Settings.JWTSettings> jwtSettings)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var refreshToken = context.Request.Cookies["refresh_token"];

            // Ako nema tokena ili refresh tokena, nastavite sa sljedećim middleware-om
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(refreshToken))
            {
                await _next(context);
                return;
            }

            var isTokenExpired = IsTokenExpired(token, jwtSettings.Value.Secret);

            // Ako token nije istekao, nastavite sa sljedećim middleware-om
            if (!isTokenExpired)
            {
                await _next(context);
                return;
            }

            try
            {
                // Token je istekao, ali imamo refresh token - pokušajmo osvježiti token
                _logger.LogInformation("JWT token je istekao, pokušavamo ga osvježiti pomoću refresh tokena");

                var request = new RefreshTokenRequest
                {
                    Token = token,
                    RefreshToken = refreshToken
                };

                var response = await authService.RefreshTokenAsync(request);

                // Postavite novi refresh token u cookie
                SetRefreshTokenCookie(context, response.RefreshToken);
                response.RefreshToken = null;

                // Postavite novi JWT token u header
                context.Request.Headers["Authorization"] = $"Bearer {response.Token}";

                _logger.LogInformation("JWT token uspješno osvježen");
            }
            catch (Exception ex)
            {
                // Ako osvježavanje ne uspije, logirajte grešku ali nastavite sa zahtjevom
                // Autentifikacija će svakako biti odbijena ako token nije valjan
                _logger.LogWarning(ex, "Greška prilikom automatskog osvježavanja JWT tokena");
            }

            await _next(context);
        }

        private bool IsTokenExpired(string token, string secret)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(secret);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                return jwtToken.ValidTo < DateTime.UtcNow;
            }
            catch
            {
                // Ako validacija izbaci iznimku, smatramo da je token istekao ili neispravan
                return true;
            }
        }

        private void SetRefreshTokenCookie(HttpContext context, string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7),
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            };

            context.Response.Cookies.Append("refresh_token", refreshToken, cookieOptions);
        }
    }

    // Extension metoda za lakšu registraciju middlewarea
    public static class JwtAutoRefreshMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtAutoRefresh(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtAutoRefreshMiddleware>();
        }
    }
}