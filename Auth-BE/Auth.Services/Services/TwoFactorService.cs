using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Models.Request;
using Auth.Models.Response;
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

        public async Task<string> GenerateTwoFactorCodeAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found during 2FA code generation", userId);
                throw new NotFoundException("User", userId);
            }

            // Koristite "Email" token provider umjesto authenticator providera
            var token = await _userManager.GenerateUserTokenAsync(
                user,
                TokenOptions.DefaultEmailProvider, // Koristi email provider
                "EmailAuthenticator" // Svrha tokena
            );

            _logger.LogInformation("2FA code generated for user {UserId}: {Token}", userId, token);
            return token;
        }


        public async Task<AuthResponse> ValidateTwoFactorAsync(TwoFactorRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning("User with email {Email} not found during 2FA validation", request.Email);
                throw new NotFoundException("User with this email does not exist");
            }

            // Koristite isti način verifikacije 
            var isValid = await _userManager.VerifyUserTokenAsync(
                user,
                TokenOptions.DefaultEmailProvider,
                "EmailAuthenticator",
                request.TwoFactorCode
            );

            if (!isValid)
            {
                _logger.LogWarning("Invalid 2FA code for user {Email}", request.Email);
                throw new AuthenticationException("Invalid verification code");
            }

            // Generate tokens
            var jwtToken = await _tokenService.GenerateJwtTokenAsync(user);
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user);

            return new AuthResponse
            {
                Token = jwtToken,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(15), // Trebalo bi odgovarati JWT isteku
                RequiresTwoFactor = false,
                EmailConfirmed = user.EmailConfirmed
            };
        }
    }
}
