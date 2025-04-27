using Auth.Models.DTOs;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Services.Interfaces;
using Auth.Services.Settings;
using DotNetEnv;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Services.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly JWTSettings _jwtSettings;
        private readonly SignInManager<User> _signInManager;

        public AuthService(UserManager<User> userManager, IOptions<JWTSettings> jwtSettings, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings.Value;
            _signInManager = signInManager;
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                throw new ConflictException($"Email {request.Email} je već registriran.");
            }

            var user = new User
            {
                Email = request.Email,
                UserName = request.Email,
                FirstName = request.FirstName ?? string.Empty,
                LastName = request.LastName ?? string.Empty,
                CreatedAt = DateTime.UtcNow,
                IsActive = true,
                RefreshToken = null
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                throw new ValidationException(string.Join(", ", errors));
            }

            await _userManager.AddToRoleAsync(user, "User");

            return await GenerateTokensAsync(user);
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                throw new AuthenticationException("Nevažeći email ili lozinka.");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
            {
                throw new AuthenticationException("Nevažeći email ili lozinka.");
            }

            if (user.TwoFactorEnabled)
            {
                return new AuthResponse
                {
                    RequiresTwoFactor = true
                };
            }

            return await GenerateTokensAsync(user);
        }

        public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            var principal = GetPrincipalFromExpiredToken(request.Token);
            var username = principal.Identity.Name;

            var user = await _userManager.FindByNameAsync(username);

            if (user == null ||
                user.RefreshToken != request.RefreshToken ||
                user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                throw new AuthenticationException("Nevažeći refresh token.");
            }

            return await GenerateTokensAsync(user);
        }

        public async Task<AuthResponse> ValidateTwoFactorAsync(TwoFactorRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                throw new AuthenticationException("Korisnik nije pronađen.");
            }

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                request.TwoFactorCode);

            if (!isValid)
            {
                throw new AuthenticationException("Nevažeći 2FA kod.");
            }

            return await GenerateTokensAsync(user);
        }

        public async Task<bool> SetupTwoFactorAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return true;
        }

        public async Task<string> GenerateTwoFactorCodeAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            return await _userManager.GenerateTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider);
        }

        public async Task<bool> VerifyTwoFactorCodeAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            return await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);
        }

        public async Task<bool> LogoutAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            return true;
        }


        private async Task<AuthResponse> GenerateTokensAsync(User user)
        {
            var token = await GenerateJwtTokenAsync(user);

            var refreshToken = GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);
            await _userManager.UpdateAsync(user);

            return new AuthResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Expiration = token.ValidTo,
                RequiresTwoFactor = false
            };
        }

        private async Task<JwtSecurityToken> GenerateJwtTokenAsync(User user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);

            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();
            foreach (var role in roles)
            {
                roleClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var secret = Env.GetString("JWT_SECRET");
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (!(securityToken is JwtSecurityToken jwtSecurityToken) ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Nevažeći token.");
            }

            return principal;
        }

    }

}

