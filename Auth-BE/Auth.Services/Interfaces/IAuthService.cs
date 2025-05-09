using Auth.Models.DTOs;

namespace Auth.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress = null);
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress = null);
        Task<bool> LogoutAsync(string userId, string refreshToken = null);
    }
}
