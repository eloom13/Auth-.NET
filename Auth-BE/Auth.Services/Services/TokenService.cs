using Auth.Models.Data;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
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
        private readonly ILogger<TokenService> _logger;

        public TokenService(UserManager<User> userManager, ApplicationDbContext context, IOptions<JWTSettings> jwtSettings, ILogger<TokenService> logger)
        {
            _userManager = userManager;
            _context = context;
            _jwtSettings = jwtSettings.Value;
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

        public async Task<string> GenerateRefreshTokenAsync(User user, string ipAddress = null)
        {
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
                CreatedByIp = ipAddress
            };

            _logger.LogInformation($"Generating new refresh token for user {user.Id}, expires at {refreshTokenEntity.ExpiryTime}",
                user.Id, refreshTokenEntity.ExpiryTime);

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            return refreshToken;
        }

        public async Task<User> ValidateRefreshTokenAsync(string token, string refreshToken)
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
                _logger.LogWarning($"Refresh token has been revoked for user {userId}");
                throw new AuthenticationException("Refresh token has been revoked.");
            }

            _logger.LogInformation($"Refresh token successfully validated for user {userId}");
            return user;
        }

        public async Task RevokeRefreshTokenAsync(string refreshToken, string userId, string ipAddress = null)
        {
            var token = await _context.RefreshTokens
                .SingleOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == userId);

            if (token == null)
            {
                _logger.LogWarning($"Attempt to revoke non-existent refresh token for user {userId}");
                return;
            }

            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;

            _context.RefreshTokens.Update(token);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Refresh token successfully revoked for user {userId}");
        }

        public async Task RevokeAllRefreshTokensAsync(string userId)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && rt.RevokedAt == null)
                .ToListAsync();

            if (!tokens.Any())
            {
                _logger.LogInformation($"No active refresh tokens for user {userId}");
                return;
            }

            foreach (var token in tokens)
            {
                token.RevokedAt = DateTime.UtcNow;
            }

            _context.RefreshTokens.UpdateRange(tokens);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Revoked {tokens.Count} refresh tokens for user {userId}");
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
