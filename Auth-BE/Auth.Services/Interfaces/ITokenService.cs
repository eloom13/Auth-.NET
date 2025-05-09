using Auth.Models.Entities;
using System.Security.Claims;

namespace Auth.Services.Interfaces
{
    public interface ITokenService
    {
        Task<string> GenerateJwtTokenAsync(User user);
        Task<string> GenerateRefreshTokenAsync(User user, string ipAddress = null);
        Task<User> ValidateRefreshTokenAsync(string token, string refreshToken);
        Task RevokeRefreshTokenAsync(string refreshToken, string userId, string ipAddress = null);
        Task RevokeAllRefreshTokensAsync(string userId);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
