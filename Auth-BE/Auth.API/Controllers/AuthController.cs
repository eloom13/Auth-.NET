using Auth.API.Helpers;
using Auth.Models.DTOs;
using Auth.Models.Response;
using Auth.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Auth.API.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly ITwoFactorService _twoFactorService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IUserService userService,
            ITwoFactorService twoFactorService,
            IHttpContextAccessor httpContextAccessor,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _twoFactorService = twoFactorService;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request);

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Registration successful"));
        }

        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest request)
        {
            try
            {
                var ipAddress = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
                _logger.LogInformation("Login request from IP: {IpAddress}", ipAddress ?? "Unknown");

                var result = await _authService.LoginAsync(request, ipAddress);

                if (result.RequiresTwoFactor)
                {
                    return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "2FA verification required"));
                }

                CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

                result.RefreshToken = null;

                return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Login successful"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for {Email}", request.Email);
                throw;
            }
        }

        [Authorize]
        [HttpGet("current-user")]
        public async Task<ActionResult<ApiResponse<CurrentUserResponse>>> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userService.GetCurrentUserAsync(userId);

            return Ok(ApiResponse<CurrentUserResponse>.SuccessResponse(user, "User Data"));
        }

        [Authorize]
        [HttpPost("setup-2fa")]
        public async Task<ActionResult<ApiResponse<bool>>> SetupTwoFactor()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _twoFactorService.SetupTwoFactorAsync(userId);
            return Ok(ApiResponse<bool>.SuccessResponse(result, "2FA enabled"));
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<ActionResult<ApiResponse<bool>>> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var refreshToken = Request.Cookies["refresh_token"];
            var result = await _authService.LogoutAsync(userId, refreshToken);

            Response.Cookies.Delete("refresh_token");

            return Ok(ApiResponse<bool>.SuccessResponse(result, "Logout successful"));
        }

        /*
        [Authorize]
        [HttpGet("generate-2fa-code")]
        public async Task<ActionResult<ApiResponse<string>>> GenerateTwoFactorCode()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var code = await _twoFactorService.GenerateTwoFactorCodeAsync(userId);
            return Ok(ApiResponse<string>.SuccessResponse(code, "2FA kod generiran"));
        }

        [Authorize]
        [HttpPost("verify-2fa-code")]
        public async Task<ActionResult<ApiResponse<bool>>> VerifyTwoFactorCode([FromBody] string code)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _twoFactorService.VerifyTwoFactorCodeAsync(userId, code);
            return Ok(ApiResponse<bool>.SuccessResponse(result, "2FA kod verificiran"));
        }

        [HttpPost("two-factor")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> TwoFactorVerify([FromBody] TwoFactorRequest request)
        {
            var result = await _twoFactorService.ValidateTwoFactorAsync(request);

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

            // Ne šaljemo refresh token u response
            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "2FA verifikacija uspješna"));
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var refreshToken = Request.Cookies["refresh_token"];

            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(ApiResponse<AuthResponse>.ErrorResponse("Refresh token nije pronađen", null, 401));
            }

            var completeRequest = new RefreshTokenRequest
            {
                Token = request.Token,
                RefreshToken = refreshToken
            };

            var ipAddress = _httpContextAccessor.HttpContext.Connection.RemoteIpAddress?.ToString();
            var result = await _authenticationService.RefreshTokenAsync(completeRequest, ipAddress);

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

            // Ne šaljemo refresh token u response
            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Token osvježen"));
        }
        */
    }
}