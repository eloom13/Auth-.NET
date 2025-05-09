using Auth.Models.DTOs;
using Auth.Models.Entities;

namespace Auth.Services.Interfaces
{
    public interface IUserService
    {
        Task<CurrentUserResponse> GetCurrentUserAsync(string userId);
        Task<User> CreateUserAsync(RegisterRequest request);
        Task<(bool Succeeded, User User, bool RequiresTwoFactor)> VerifyCredentialsAsync(string email, string password);
    }
}
