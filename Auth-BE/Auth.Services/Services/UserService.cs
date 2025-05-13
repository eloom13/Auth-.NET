using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Models.Request;
using Auth.Models.Response;
using Auth.Services.Interfaces;
using MapsterMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Auth.Services.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<UserService> _logger;
        private readonly IMapper _mapper;

        public UserService(UserManager<User> userManager, SignInManager<User> signInManager, ILogger<UserService> logger, IMapper mapper)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _mapper = mapper;
        }

        public async Task<User> GetUserAsync(string identifier, bool byEmail = false, bool throwIfNotFound = true)
        {
            User user = null;
            string idType = byEmail ? "email" : "ID";

            if (byEmail)
                user = await _userManager.FindByEmailAsync(identifier);
            else
                user = await _userManager.FindByIdAsync(identifier);

            if (user == null)
            {
                _logger.LogWarning("User with {IdType} {Identifier} not found", idType, identifier);

                if (throwIfNotFound)
                {
                    if (byEmail)
                        throw new NotFoundException($"User with email {identifier}", null);
                    else
                        throw new NotFoundException("User", identifier);
                }
            }

            return user;
        }

        public async Task<User> CreateUserAsync(RegisterRequest request)
        {
            var existingUser = await GetUserAsync(request.Email, byEmail: true, throwIfNotFound: false);
            if (existingUser != null)
            {
                _logger.LogWarning("User with email {Email} already exists", request.Email);
                throw new ConflictException($"User with this {request.Email} email already exists");
            }

            var user = _mapper.Map<User>(request);
            user.UserName = request.Email;
            user.CreatedAt = DateTime.UtcNow;
            user.IsActive = true;
            user.TwoFactorEnabled = false;
            user.EmailConfirmed = false;

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                var errorMessage = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("User creation failed: {Errors}", errorMessage);
                throw new ValidationException(errorMessage);
            }

            await _userManager.AddToRoleAsync(user, "User");
            _logger.LogInformation("User {Email} created successfully", request.Email);
            return user;
        }

        public async Task<CurrentUserResponse> GetCurrentUserAsync(string userId)
        {
            var user = await GetUserAsync(userId, throwIfNotFound: true);
            var roles = await _userManager.GetRolesAsync(user);

            var currentUserResponse = _mapper.Map<CurrentUserResponse>(user);
            currentUserResponse.Roles = roles.ToList();
            currentUserResponse.IsTwoFactorEnabled = user.TwoFactorEnabled;
            currentUserResponse.EmailConfirmed = user.EmailConfirmed;

            return currentUserResponse;
        }

        public async Task<(bool Succeeded, User User, bool RequiresTwoFactor, bool EmailNotConfirmed)> VerifyCredentialsAsync(string email, string password)
        {
            var user = await GetUserAsync(email, byEmail: true, throwIfNotFound: false);
            if (user == null)
                return (false, null, false, false);

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed login for user {Email} - invalid password", email);
                return (false, null, false, false);
            }

            bool emailNotConfirmed = !user.EmailConfirmed;
            if (emailNotConfirmed)
                _logger.LogInformation("Login for user {Email} with unconfirmed email", email);

            if (user.TwoFactorEnabled)
            {
                _logger.LogInformation("Login requires 2FA for user {Email}", email);
                return (true, user, true, emailNotConfirmed);
            }

            _logger.LogInformation("Successful login for user {Email}", email);
            return (true, user, false, emailNotConfirmed);
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(string userId)
        {
            var user = await GetUserAsync(userId, throwIfNotFound: true);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            _logger.LogInformation("Email confirmation token generated for user {Email}", user.Email);
            return token;
        }

        public async Task<bool> ConfirmEmailAsync(string userId, string token)
        {
            var user = await GetUserAsync(userId, throwIfNotFound: true);
            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to confirm email for user {Email}: {Errors}", user.Email, errors);
                return false;
            }

            _logger.LogInformation("Email confirmed for user {Email}", user.Email);
            return true;
        }

        public async Task<User> GetUserByEmailAsync(string email)
        {
            return await GetUserAsync(email, byEmail: true, throwIfNotFound: false);
        }

        public async Task<string> GetUserEmailByIdAsync(string userId)
        {
            var user = await GetUserAsync(userId, throwIfNotFound: true);
            return user.Email;
        }
    }
}