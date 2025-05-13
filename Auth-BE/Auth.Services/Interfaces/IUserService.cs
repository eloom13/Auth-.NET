using Auth.Models.Entities;
using Auth.Models.Request;
using Auth.Models.Response;

namespace Auth.Services.Interfaces
{
    public interface IUserService
    {
        Task<CurrentUserResponse> GetCurrentUserAsync(string userId);
        Task<User> CreateUserAsync(RegisterRequest request);
        Task<(bool Succeeded, User User, bool RequiresTwoFactor, bool EmailNotConfirmed)> VerifyCredentialsAsync(string email, string password);
        Task<string> GenerateEmailConfirmationTokenAsync(string userId);
        Task<bool> ConfirmEmailAsync(string userId, string token);
        Task<User> GetUserByEmailAsync(string email);
        Task<string> GetUserEmailByIdAsync(string userId);
    }
}