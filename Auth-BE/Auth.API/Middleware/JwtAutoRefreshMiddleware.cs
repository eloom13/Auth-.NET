using Auth.API.Helpers;
using Auth.Models.DTOs;
using Auth.Services.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Auth.API.Middleware
{
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

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(refreshToken))
            {
                await _next(context);
                return;
            }

            var isTokenExpired = IsTokenExpired(token, jwtSettings.Value.Secret);

            if (!isTokenExpired)
            {
                await _next(context);
                return;
            }

            try
            {
                _logger.LogInformation("JWT token je istekao, pokušavamo ga osvježiti pomoću refresh tokena");

                var request = new RefreshTokenRequest
                {
                    Token = token,
                    RefreshToken = refreshToken
                };

                var response = await authService.RefreshTokenAsync(request);

                CookieHelper.SetRefreshTokenCookie(context, response.RefreshToken);


                // ✅ Optionally save new access token in HttpOnly cookie
                /*
                context.Response.Cookies.Append("access_token", response.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = "/",
                    Expires = DateTime.UtcNow.AddMinutes(15)
                });
                */

                // Optional: also expose token in a response header (for frontend to pick up)
                context.Response.Headers["X-New-Token"] = response.Token;


                _logger.LogInformation("JWT token uspješno osvježen");
            }
            catch (Exception ex)
            {
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
                return true;
            }
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