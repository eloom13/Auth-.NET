using Auth.Models.DTOs;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
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

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                var errorMessage = string.Join(", ", errors);
                _logger.LogError("Failed to create user: {Errors}", errorMessage);
                throw new ValidationException($"Failed to create user: {errorMessage}");
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

            return currentUserResponse;
        }


        public async Task<(bool Succeeded, User User, bool RequiresTwoFactor)> VerifyCredentialsAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                _logger.LogWarning("Login attempt with non-existent email: {Email}", email);
                return (false, null, false);
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed login for user {Email} - invalid password", email);
                return (false, null, false);
            }

            if (user.TwoFactorEnabled)
            {
                _logger.LogInformation("Login requires 2FA for user {Email}", email);
                return (true, user, true);
            }

            _logger.LogInformation("Successful login for user {Email}", email);
            return (true, user, false);

        }
    }
}
