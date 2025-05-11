using Auth.API.Helpers;
using Auth.Models.Response;
using Auth.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;
using System.Text;
using LoginRequest = Auth.Models.Request.LoginRequest;
using RegisterRequest = Auth.Models.Request.RegisterRequest;
using ResendConfirmationEmailRequest = Auth.Models.Request.ResendConfirmationEmailRequest;

namespace Auth.API.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly ITwoFactorService _twoFactorService;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IUserService userService,
            ITwoFactorService twoFactorService,
            IEmailService emailService,
            IHttpContextAccessor httpContextAccessor,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _twoFactorService = twoFactorService;
            _emailService = emailService;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse<RegisterResponse>>> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request);

            if (result.User != null)
            {
                var confirmationToken = await _userService.GenerateEmailConfirmationTokenAsync(result.User.Id);
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));

                var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={result.User.Id}&token={encodedToken}";

                await _emailService.SendEmailConfirmationAsync(result.User.Email, callbackUrl);
            }

            return Ok(ApiResponse<RegisterResponse>.SuccessResponse(
                new RegisterResponse
                {
                    UserId = result.User.Id,
                    Email = result.User.Email,
                    RequiresEmailConfirmation = true
                },
                "Registration successful. Please check your email to confirm your account."));
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return BadRequest(ApiResponse<bool>.ErrorResponse("Invalid email confirmation link.", null, 400));
            }

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userService.ConfirmEmailAsync(userId, decodedToken);

            if (result)
            {
                // You could redirect to a frontend page or return a view
                return Ok(ApiResponse<bool>.SuccessResponse(true, "Email confirmed successfully. You can now log in to your account."));
            }

            return BadRequest(ApiResponse<bool>.ErrorResponse("Failed to confirm email.", null, 400));
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
        {
            var user = await _userService.GetUserByEmailAsync(request.Email);

            if (user == null)
            {
                // We don't want to reveal that the email doesn't exist for security reasons
                return Ok(ApiResponse<bool>.SuccessResponse(true, "If your email exists in our system, a confirmation email has been sent."));
            }

            if (user.EmailConfirmed)
            {
                return Ok(ApiResponse<bool>.SuccessResponse(true, "Your email is already confirmed."));
            }

            var confirmationToken = await _userService.GenerateEmailConfirmationTokenAsync(user.Id);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));

            var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&token={encodedToken}";

            await _emailService.SendEmailConfirmationAsync(user.Email, callbackUrl);

            return Ok(ApiResponse<bool>.SuccessResponse(true, "Confirmation email has been sent. Please check your inbox."));
        }

        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest request)
        {
            try
            {
                var ipAddress = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
                _logger.LogInformation("Login request from IP: {IpAddress}", ipAddress ?? "Unknown");

                var result = await _authService.LoginAsync(request, ipAddress);

                // Allow login even if email is not confirmed, but include the information in the response
                if (result.EmailNotConfirmed)
                {
                    // Set refresh token cookie
                    CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);
                    result.RefreshToken = null;

                    // Return successful login but with a message about unconfirmed email
                    return Ok(ApiResponse<AuthResponse>.SuccessResponse(
                        result,
                        "Login successful. Note: Your email is not yet confirmed. Some features may be limited until you confirm your email."
                    ));
                }

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