using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Auth.Services.Services
{
    public class TwoFactorService : ITwoFactorService
    {
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ILogger<TwoFactorService> _logger;

        public TwoFactorService(UserManager<User> userManager, ITokenService tokenService, ILogger<TwoFactorService> logger)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _logger = logger;
        }

        public async Task<bool> SetupTwoFactorAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found during 2FA setup", userId);
                throw new NotFoundException("User", userId);
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to set up 2FA for user {UserId}: {Errors}", userId, errors);
                throw new ValidationException($"Error setting up 2FA: {errors}");
            }

            _logger.LogInformation("2FA successfully set up for user {UserId}", userId);
            return true;
        }
    }
}
