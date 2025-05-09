using Auth.Models.DTOs;
using Auth.Models.Exceptions;
using Auth.Services.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Services.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<IAuthService> _logger;

        public AuthService(
            IUserService userService,
            ITokenService tokenService,
            ILogger<IAuthService> logger)
        {
            _userService = userService;
            _tokenService = tokenService;
            _logger = logger;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            _logger.LogInformation("Starting registration for email {Email}", request.Email);

            var user = await _userService.CreateUserAsync(request);

            var jwtToken = await _tokenService.GenerateJwtTokenAsync(user);
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user);

            var response = new AuthResponse
            {
                Token = jwtToken,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(15),
                RequiresTwoFactor = false
            };

            _logger.LogInformation("Registration successful for user {Email}", user.Email);
            return response;
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress = null)
        {
            _logger.LogInformation("Starting login for email {Email}", request.Email);

            var (succeeded, user, requiresTwoFactor) = await _userService.VerifyCredentialsAsync(request.Email, request.Password);

            if (!succeeded)
            {
                _logger.LogWarning("Failed login attempt for email {Email} - invalid credentials", request.Email);
                throw new AuthenticationException("Invalid email or password.");
            }

            if (requiresTwoFactor)
            {
                _logger.LogInformation("Login requires 2FA for user {Email}", request.Email);
                return new AuthResponse
                {
                    RequiresTwoFactor = true
                };
            }

            var jwtToken = await _tokenService.GenerateJwtTokenAsync(user);
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user, ipAddress);

            var response = new AuthResponse
            {
                Token = jwtToken,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(15), // This should come from the actual JWT token expiration time
                RequiresTwoFactor = false
            };

            _logger.LogInformation("Login successful for user {Email}", user.Email);
            return response;
        }

        public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress = null)
        {
            _logger.LogInformation("Starting token refresh");

            try
            {
                var user = await _tokenService.ValidateRefreshTokenAsync(request.Token, request.RefreshToken);

                await _tokenService.RevokeRefreshTokenAsync(request.RefreshToken, user.Id, ipAddress);

                var jwtToken = await _tokenService.GenerateJwtTokenAsync(user);
                var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync(user, ipAddress);

                // Prepare response
                var response = new AuthResponse
                {
                    Token = jwtToken,
                    RefreshToken = newRefreshToken,
                    Expiration = DateTime.UtcNow.AddMinutes(15), // This should come from the actual JWT token expiration time
                    RequiresTwoFactor = false
                };

                _logger.LogInformation("Token successfully refreshed for user {Email}", user.Email);
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error occurred while refreshing token");
                throw;
            }
        }

        public async Task<bool> LogoutAsync(string userId, string refreshToken = null)
        {
            _logger.LogInformation("Starting logout for user {UserId}", userId);

            try
            {
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    await _tokenService.RevokeRefreshTokenAsync(refreshToken, userId);
                    _logger.LogInformation("Specific refresh token revoked for user {UserId}", userId);
                }
                else
                {
                    await _tokenService.RevokeAllRefreshTokensAsync(userId);
                    _logger.LogInformation("All refresh tokens revoked for user {UserId}", userId);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error occurred while logging out user {UserId}", userId);
                throw;
            }
        }
    }
}
