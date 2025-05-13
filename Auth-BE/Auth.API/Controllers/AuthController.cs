using Auth.API.Helpers;
using Auth.Models.Request;
using Auth.Models.Response;
using Auth.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
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

                // Use queue-based email method instead of direct sending
                _emailService.QueueEmailConfirmationAsync(result.User.Email, callbackUrl);

                var loginResult = await _authService.LoginAsync(new LoginRequest
                {
                    Email = request.Email,
                    Password = request.Password
                });

                CookieHelper.SetRefreshTokenCookie(HttpContext, loginResult.RefreshToken);
                loginResult.RefreshToken = null;

                // Return response with tokens and user info
                return Ok(ApiResponse<RegisterResponse>.SuccessResponse(
                    new RegisterResponse
                    {
                        UserId = result.User.Id,
                        Email = result.User.Email,
                        RequiresEmailConfirmation = true,
                        Token = loginResult.Token,
                        Expiration = loginResult.Expiration
                    },
                    "Registration successful. Please check your email to confirm your account. You're now logged in."));
            }

            return Ok(ApiResponse<RegisterResponse>.SuccessResponse(result.Response, "Registration successful. Please check your email to confirm your account."));
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return Content(EmailConfirmationBuilder.GetErrorHtml("Invalid email confirmation link. The link appears to be missing required information."), "text/html");
            }

            try
            {
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                var result = await _userService.ConfirmEmailAsync(userId, decodedToken);

                if (result)
                {
                    return Content(EmailConfirmationBuilder.GetSuccessHtml(), "text/html");
                }
                else
                {
                    return Content(EmailConfirmationBuilder.GetErrorHtml("We couldn't confirm your email. The verification link may have expired or was already used."), "text/html");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error confirming email for user {UserId}", userId);
                return Content(EmailConfirmationBuilder.GetErrorHtml("An error occurred while trying to confirm your email. Please try again later."), "text/html");
            }
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
        {
            var user = await _userService.GetUserByEmailAsync(request.Email);

            if (user == null)
            {
                // We don't reveal whether the email exists in the system for security reasons
                return Ok(ApiResponse<bool>.SuccessResponse(true, "If your email address exists in our system, a confirmation email has been sent."));
            }

            if (user.EmailConfirmed)
            {
                return Ok(ApiResponse<bool>.SuccessResponse(true, "Your email address is already confirmed."));
            }

            var confirmationToken = await _userService.GenerateEmailConfirmationTokenAsync(user.Id);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));

            var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&token={encodedToken}";

            // Instead of sending the email directly, enqueue it using a message queue (e.g., RabbitMQ)
            _emailService.QueueEmailConfirmationAsync(user.Email, callbackUrl);

            return Ok(ApiResponse<bool>.SuccessResponse(true, "A confirmation email has been sent. Please check your inbox."));
        }

        [EnableRateLimiting("auth")]
        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest request)
        {
            try
            {
                var ipAddress = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
                _logger.LogInformation("Login request from IP: {IpAddress}", ipAddress ?? "Unknown");

                var result = await _authService.LoginAsync(request, ipAddress);

                // Only set the refresh token cookie if it's not null or empty
                if (!string.IsNullOrEmpty(result.RefreshToken))
                {
                    CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);
                    result.RefreshToken = null; // Clear after setting cookie
                }

                // Check for unconfirmed email
                if (!result.EmailConfirmed)
                {
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

        [Authorize]
        [HttpGet("generate-2fa-code")]
        public async Task<ActionResult<ApiResponse<string>>> GenerateTwoFactorCode()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Dohvati email korisnika
            var userEmail = await _userService.GetUserEmailByIdAsync(userId);

            // Generiraj kod za 2FA
            var code = await _twoFactorService.GenerateTwoFactorCodeAsync(userId);

            // Pošalji kod putem e-maila
            _emailService.Queue2FACodeAsync(userEmail, code);

            return Ok(ApiResponse<string>.SuccessResponse(
                "Check your email for the verification code",
                "A verification code has been sent to your email address. The code will expire in 15 minutes."
            ));
        }

        [HttpPost("two-factor")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> TwoFactorVerify([FromBody] TwoFactorRequest request)
        {
            var result = await _twoFactorService.ValidateTwoFactorAsync(request);

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

            // Don't send refresh token in response
            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "2FA verification successful"));
        }
    }
}