using Auth.Models.DTOs;

namespace Auth.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(LoginRequest request);
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request);
        Task<AuthResponse> ValidateTwoFactorAsync(TwoFactorRequest request);
        Task<bool> SetupTwoFactorAsync(string userId);
        Task<string> GenerateTwoFactorCodeAsync(string userId);
        Task<bool> VerifyTwoFactorCodeAsync(string userId, string code);
        Task<bool> LogoutAsync(string userId);
    }
}
