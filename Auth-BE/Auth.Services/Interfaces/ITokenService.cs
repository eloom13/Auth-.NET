using Auth.Models.Entities;
using Auth.Models.Response;
using System.Security.Claims;

namespace Auth.Services.Interfaces
{
    public interface ITokenService
    {
        Task<string> GenerateJwtTokenAsync(User user);
        Task<string> GenerateRefreshTokenAsync(User user, string ipAddress = null);
        Task<User> ValidateRefreshTokenAsync(string token, string refreshToken, string ipAddress = null);
        Task<AuthResponse> RotateRefreshTokenAsync(string jwtToken, string refreshToken, string userId, string ipAddress = null);
        Task RevokeRefreshTokenAsync(string refreshToken, string userId, string ipAddress = null, string reason = null);
        Task RevokeAllRefreshTokensAsync(string userId, string ipAddress = null, string reason = null);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}