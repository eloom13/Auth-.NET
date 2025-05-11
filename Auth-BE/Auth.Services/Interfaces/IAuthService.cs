using Auth.Models.Entities;
using Auth.Models.Request;
using Auth.Models.Response;

namespace Auth.Services.Interfaces
{
    public interface IAuthService
    {
        Task<(User User, RegisterResponse Response)> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress = null);
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress = null);
        Task<bool> LogoutAsync(string userId, string refreshToken = null);
    }
}