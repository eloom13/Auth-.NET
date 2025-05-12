using Auth.Models.Request;
using Auth.Models.Response;

namespace Auth.Services.Interfaces
{
    public interface ITwoFactorService
    {
        Task<bool> SetupTwoFactorAsync(string userId);
        Task<string> GenerateTwoFactorCodeAsync(string userId);
        Task<AuthResponse> ValidateTwoFactorAsync(TwoFactorRequest request);
    }
}
