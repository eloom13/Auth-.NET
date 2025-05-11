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

        public async Task<User> CreateUserAsync(RegisterRequest request)
        {
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
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
            user.EmailConfirmed = false;  // Set email as not confirmed initially

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                var errorMessage = string.Join(", ", errors);
                _logger.LogError("{Errors}", errorMessage);
                throw new ValidationException($"{errorMessage}");
            }

            await _userManager.AddToRoleAsync(user, "User");
            _logger.LogInformation("User {Email} created successfully", request.Email);

            return user;
        }

        public async Task<CurrentUserResponse> GetCurrentUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found", userId);
                throw new NotFoundException("User", userId);
            }

            var roles = await _userManager.GetRolesAsync(user);

            var currentUserResponse = _mapper.Map<CurrentUserResponse>(user);
            currentUserResponse.Roles = roles.ToList();
            currentUserResponse.IsTwoFactorEnabled = user.TwoFactorEnabled;
            currentUserResponse.EmailConfirmed = user.EmailConfirmed;

            return currentUserResponse;
        }

        public async Task<(bool Succeeded, User User, bool RequiresTwoFactor, bool EmailNotConfirmed)> VerifyCredentialsAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("Login attempt with non-existent email: {Email}", email);
                return (false, null, false, false);
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed login for user {Email} - invalid password", email);
                return (false, null, false, false);
            }

            // Check if email is confirmed, but don't block login
            bool emailNotConfirmed = !user.EmailConfirmed;
            if (emailNotConfirmed)
            {
                _logger.LogInformation("Login for user {Email} with unconfirmed email", email);
            }

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
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found when generating email confirmation token", userId);
                throw new NotFoundException("User", userId);
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            _logger.LogInformation("Email confirmation token generated for user {Email}", user.Email);

            return token;
        }

        public async Task<bool> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found when confirming email", userId);
                throw new NotFoundException("User", userId);
            }

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
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("User with email {Email} not found", email);
                // We're not throwing an exception here to handle this case in the controller
            }

            return user;
        }
    }
}