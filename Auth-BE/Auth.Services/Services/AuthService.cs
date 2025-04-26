using Auth.Models.DTOs;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Services.Interfaces;
using Auth.Services.Settings;
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
                FirstName = request.FirstName,
                LastName = request.LastName,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
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
            // Pronalazak korisnika
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            // Generiranje jednokratnog koda za 2FA
            return await _userManager.GenerateTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider);
        }

        public async Task<bool> VerifyTwoFactorCodeAsync(string userId, string code)
        {
            // Pronalazak korisnika
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            // Provjera 2FA koda
            return await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);
        }

        public async Task<bool> LogoutAsync(string userId)
        {
            // Pronalazak korisnika
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new NotFoundException("Korisnik", userId);
            }

            // Invalidacija refresh tokena
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            return true;
        }


        private async Task<AuthResponse> GenerateTokensAsync(User user)
        {
            // Generiranje JWT tokena
            var token = await GenerateJwtTokenAsync(user);

            // Generiranje refresh tokena
            var refreshToken = GenerateRefreshToken();

            // Spremanje refresh tokena u bazu
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);
            await _userManager.UpdateAsync(user);

            // Kreiranje odgovora
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
            // Dohvat korisničkih claimova
            var userClaims = await _userManager.GetClaimsAsync(user);

            // Dohvat korisničkih uloga
            var roles = await _userManager.GetRolesAsync(user);

            // Kreiranje claimova za uloge
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
            {
                roleClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Kombiniranje svih claimova
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

            // Kreiranje ključa za potpisivanje
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            // Kreiranje JWT tokena
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
            // Kreiranje random bytea za refresh token
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            // Parametri za validaciju tokena - ne provjeravamo istek tokena
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false // Ne validiramo istek tokena jer on može biti istekao
            };

            // Validacija tokena
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            // Provjera je li token valjanog tipa i algoritma
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Nevažeći token.");
            }

            return principal;
        }

    }

}

