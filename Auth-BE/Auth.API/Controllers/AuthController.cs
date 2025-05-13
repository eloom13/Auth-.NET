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

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IUserService _userService;
    private readonly ITwoFactorService _twoFactorService;
    private readonly IEmailService _emailService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IAuthService authService,
        IUserService userService,
        ITwoFactorService twoFactorService,
        IEmailService emailService,
        ILogger<AuthController> logger)
    {
        _authService = authService;
        _userService = userService;
        _twoFactorService = twoFactorService;
        _emailService = emailService;
        _logger = logger;
    }

    private string GetUserId() => User.FindFirstValue(ClaimTypes.NameIdentifier);

    private string GetIpAddress() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

    [EnableRateLimiting("auth-email")]
    [HttpPost("register")]
    public async Task<ActionResult<ApiResponse<RegisterResponse>>> Register([FromBody] RegisterRequest request)
    {
        var result = await _authService.RegisterAsync(request);

        var confirmationToken = await _userService.GenerateEmailConfirmationTokenAsync(result.User.Id);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));

        var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={result.User.Id}&token={encodedToken}";
        _emailService.QueueEmailConfirmationAsync(result.User.Email, callbackUrl);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = request.Email,
            Password = request.Password
        });

        CookieHelper.SetRefreshTokenCookie(HttpContext, loginResult.RefreshToken);
        loginResult.RefreshToken = null;

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

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            return Content(EmailConfirmationBuilder.GetErrorHtml(
                "Invalid email confirmation link. The link appears to be missing required information."),
                "text/html");
        }

        try
        {
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await _userService.ConfirmEmailAsync(userId, decodedToken);

            return Content(
                result
                    ? EmailConfirmationBuilder.GetSuccessHtml()
                    : EmailConfirmationBuilder.GetErrorHtml("We couldn't confirm your email. The verification link may have expired or was already used."),
                "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user {UserId}", userId);
            return Content(EmailConfirmationBuilder.GetErrorHtml(
                "An error occurred while trying to confirm your email. Please try again later."),
                "text/html");
        }
    }

    [EnableRateLimiting("ip-only")]
    [HttpPost("resend-confirmation-email")]
    public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
    {
        var user = await _userService.GetUserByEmailAsync(request.Email);

        if (user == null || user.EmailConfirmed)
        {
            return Ok(ApiResponse<bool>.SuccessResponse(true,
                user?.EmailConfirmed == true
                    ? "Your email address is already confirmed."
                    : "If your email address exists in our system, a confirmation email has been sent."));
        }

        var confirmationToken = await _userService.GenerateEmailConfirmationTokenAsync(user.Id);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));
        var callbackUrl = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&token={encodedToken}";

        _emailService.QueueEmailConfirmationAsync(user.Email, callbackUrl);

        return Ok(ApiResponse<bool>.SuccessResponse(true,
            "A confirmation email has been sent. Please check your inbox."));
    }

    [EnableRateLimiting("auth-email")]
    [HttpPost("login")]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest request)
    {
        try
        {
            string ipAddress = GetIpAddress();
            _logger.LogInformation("Login request from IP: {IpAddress}", ipAddress);

            var result = await _authService.LoginAsync(request, ipAddress);

            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);
                result.RefreshToken = null;
            }

            string message = "Login successful";

            if (!result.EmailConfirmed)
            {
                message = "Login successful. Note: Your email is not yet confirmed. Some features may be limited until you confirm your email.";
            }
            else if (result.RequiresTwoFactor)
            {
                message = "2FA verification required";
            }

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for {Email}", request.Email);
            throw;
        }
    }

    [Authorize]
    [EnableRateLimiting("email-only")]
    [HttpGet("current-user")]
    public async Task<ActionResult<ApiResponse<CurrentUserResponse>>> GetCurrentUser()
    {
        var user = await _userService.GetCurrentUserAsync(GetUserId());
        return Ok(ApiResponse<CurrentUserResponse>.SuccessResponse(user, "User Data"));
    }

    [Authorize]
    [EnableRateLimiting("email-only")]
    [HttpPost("setup-2fa")]
    public async Task<ActionResult<ApiResponse<bool>>> SetupTwoFactor()
    {
        var result = await _twoFactorService.SetupTwoFactorAsync(GetUserId());
        return Ok(ApiResponse<bool>.SuccessResponse(result, "2FA enabled"));
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<ActionResult<ApiResponse<bool>>> Logout()
    {
        var refreshToken = Request.Cookies["refresh_token"];
        var result = await _authService.LogoutAsync(GetUserId(), refreshToken);

        Response.Cookies.Delete("refresh_token");

        return Ok(ApiResponse<bool>.SuccessResponse(result, "Logout successful"));
    }

    [Authorize]
    [EnableRateLimiting("email-only")]
    [HttpGet("generate-2fa-code")]
    public async Task<ActionResult<ApiResponse<string>>> GenerateTwoFactorCode()
    {
        string userId = GetUserId();
        string userEmail = await _userService.GetUserEmailByIdAsync(userId);
        string code = await _twoFactorService.GenerateTwoFactorCodeAsync(userId);

        _emailService.Queue2FACodeAsync(userEmail, code);

        return Ok(ApiResponse<string>.SuccessResponse(
            "Check your email for the verification code",
            "A verification code has been sent to your email address. The code will expire in 15 minutes."
        ));
    }

    [EnableRateLimiting("auth-email")]
    [HttpPost("two-factor")]
    public async Task<ActionResult<ApiResponse<AuthResponse>>> TwoFactorVerify([FromBody] TwoFactorRequest request)
    {
        var result = await _twoFactorService.ValidateTwoFactorAsync(request);

        CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);
        result.RefreshToken = null;

        return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "2FA verification successful"));
    }
}