using Auth.Models.Data;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Models.Response;
using Auth.Services.Interfaces;
using Auth.Services.Settings;
using DotNetEnv;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Services.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<User> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly JWTSettings _jwtSettings;
        private readonly RefreshTokenSettings _refreshTokenSettings;
        private readonly ILogger<TokenService> _logger;

        public TokenService(UserManager<User> userManager, ApplicationDbContext context, IOptions<JWTSettings> jwtSettings, IOptions<RefreshTokenSettings> refreshTokenSettings, ILogger<TokenService> logger)
        {
            _userManager = userManager;
            _context = context;
            _jwtSettings = jwtSettings.Value;
            _refreshTokenSettings = refreshTokenSettings.Value;
            _logger = logger;
        }

        public async Task<string> GenerateJwtTokenAsync(User user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = roles.Select(role => new Claim(ClaimTypes.Role, role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("FirstName", user.FirstName ?? string.Empty),
                new Claim("LastName", user.LastName ?? string.Empty)
            }
            .Union(userClaims)
            .Union(roleClaims);

            _logger.LogInformation($"Generating JWT token for user {user.Id} with {claims.Count()} claims", user.Id, claims.Count());

            var secret = Env.GetString("JWT_SECRET");
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                signingCredentials: signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        private async Task EnforceMaxActiveSessionsAsync(string userId, string ipAddress)
        {
            var activeTokenCount = await _context.RefreshTokens
                .CountAsync(rt => rt.UserId == userId && rt.RevokedAt == null && rt.ExpiryTime > DateTime.UtcNow);

            if (activeTokenCount >= _refreshTokenSettings.MaxActiveSessionsPerUser)
            {
                _logger.LogInformation("User {UserId} has reached max sessions ({Max}). Revoking oldest session.",
                    userId, _refreshTokenSettings.MaxActiveSessionsPerUser);

                var oldestToken = await _context.RefreshTokens
                    .Where(rt => rt.UserId == userId && rt.RevokedAt == null && rt.ExpiryTime > DateTime.UtcNow)
                    .OrderBy(rt => rt.CreatedAt)
                    .FirstOrDefaultAsync();

                if (oldestToken != null)
                {
                    oldestToken.RevokedAt = DateTime.UtcNow;
                    oldestToken.RevokedByIp = ipAddress;
                    oldestToken.RevokeReason = "Revoked due to session limit";
                    await _context.SaveChangesAsync();
                }
            }
        }

        public async Task<string> GenerateRefreshTokenAsync(User user, string ipAddress = null)
        {
            if (_refreshTokenSettings.MaxActiveSessionsPerUser > 0)
            {
                await EnforceMaxActiveSessionsAsync(user.Id, ipAddress);
            }

            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            var refreshToken = Convert.ToBase64String(randomNumber);

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                ExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays),
                CreatedAt = DateTime.UtcNow,
                CreatedByIp = ipAddress,
                RefreshCount = 0,
            };

            _logger.LogInformation($"Generating new refresh token for user {user.Id}, expires at {refreshTokenEntity.ExpiryTime}",
                user.Id, refreshTokenEntity.ExpiryTime);

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            return refreshToken;
        }

        public async Task<User> ValidateRefreshTokenAsync(string token, string refreshToken, string ipAddress = null)
        {
            var principal = GetPrincipalFromExpiredToken(token);

            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ??
                        principal.FindFirstValue(JwtRegisteredClaimNames.Sub);

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Invalid token: missing identifier claim");
                throw new AuthenticationException("Invalid token: missing identifier claim.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning($"User with ID {userId} not found during refresh token validation");
                throw new AuthenticationException("User not found.");
            }

            var refreshTokenEntity = await _context.RefreshTokens
                .SingleOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == user.Id);

            if (refreshTokenEntity == null)
            {
                _logger.LogWarning($"Refresh token not found for user {userId}");
                throw new AuthenticationException("Invalid refresh token.");
            }

            if (refreshTokenEntity.IsExpired)
            {
                _logger.LogWarning($"Refresh token has expired for user {userId}");
                throw new AuthenticationException("Refresh token has expired.");
            }

            if (refreshTokenEntity.RevokedAt != null)
            {
                if (_refreshTokenSettings.DetectTokenReuse && refreshTokenEntity.ReplacedByToken != null)
                {
                    _logger.LogWarning("SECURITY ALERT: Detected refresh token reuse! Token: {Token}, User: {UserId}",
                        refreshToken, userId);

                    await RevokeAllRefreshTokensAsync(userId, ipAddress, "Token reuse detected");

                    throw new SecurityException("Invalid token use detected. For security reasons, all your sessions have been terminated.");
                }

                _logger.LogWarning("Refresh token has been revoked for user {UserId}", userId);
                throw new AuthenticationException("Refresh token has been revoked.");
            }

            if (refreshTokenEntity.RefreshCount >= _refreshTokenSettings.MaxRefreshCount)
            {
                await RevokeRefreshTokenAsync(refreshToken, userId, ipAddress, "Max refresh count exceeded");
                throw new AuthenticationException("Maximum token refresh limit reached. Please log in again.");
            }

            _logger.LogInformation($"Refresh token successfully validated for user {userId}");
            return user;
        }

        public async Task<AuthResponse> RotateRefreshTokenAsync(
            string jwtToken, string refreshToken, string userId, string ipAddress = null)
        {
            var oldToken = await _context.RefreshTokens
                .SingleOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == userId);

            if (oldToken == null)
            {
                throw new AuthenticationException("Refresh token not found.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            var newJwtToken = await GenerateJwtTokenAsync(user);

            if (_refreshTokenSettings.EnableTokenRotation)
            {
                oldToken.RefreshCount++;

                oldToken.RevokedAt = DateTime.UtcNow;
                oldToken.RevokedByIp = ipAddress;
                oldToken.RevokeReason = "Replaced by new token (normal rotation)";

                var newRefreshToken = await GenerateRefreshTokenAsync(user, ipAddress);

                oldToken.ReplacedByToken = newRefreshToken;

                await _context.SaveChangesAsync();

                return new AuthResponse
                {
                    Token = newJwtToken,
                    RefreshToken = newRefreshToken,
                    Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                    RequiresTwoFactor = false,
                    EmailConfirmed = user.EmailConfirmed
                };
            }
            else
            {
                return new AuthResponse
                {
                    Token = newJwtToken,
                    RefreshToken = refreshToken,
                    Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                    RequiresTwoFactor = false,
                    EmailConfirmed = user.EmailConfirmed
                };
            }
        }
        public async Task RevokeRefreshTokenAsync(string refreshToken, string userId, string ipAddress = null, string reason = null)
        {
            var token = await _context.RefreshTokens
                .SingleOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == userId);

            if (token == null)
            {
                _logger.LogWarning("Attempt to revoke non-existent refresh token for user {UserId}", userId);
                return;
            }

            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.RevokeReason = reason ?? "Manually revoked";

            _context.RefreshTokens.Update(token);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Refresh token successfully revoked for user {UserId}. Reason: {Reason}",
                userId, token.RevokeReason);
        }

        public async Task RevokeAllRefreshTokensAsync(string userId, string ipAddress = null, string reason = null)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && rt.RevokedAt == null)
                .ToListAsync();

            if (!tokens.Any())
            {
                _logger.LogInformation("No active refresh tokens found for user {UserId}", userId);
                return;
            }

            foreach (var token in tokens)
            {
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = ipAddress;
                token.RevokeReason = reason ?? "All tokens revocation";
            }

            _context.RefreshTokens.UpdateRange(tokens);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked {Count} refresh tokens for user {UserId}. Reason: {Reason}",
                tokens.Count, userId, reason ?? "All tokens revocation");
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ClockSkew = TimeSpan.Zero
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                if (!(securityToken is JwtSecurityToken jwtSecurityToken) ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.LogWarning("Invalid token type or signing algorithm");
                    throw new AuthenticationException("Invalid token.");
                }

                var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier) ??
                                 principal.FindFirst(JwtRegisteredClaimNames.Sub);

                if (userIdClaim == null)
                {
                    _logger.LogWarning("Token does not contain user ID");
                    throw new AuthenticationException("Token does not contain user ID.");
                }

                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error validating JWT token");
                throw new AuthenticationException($"Invalid or expired token: {ex.Message}");
            }
        }
    }
}
