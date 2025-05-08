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
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthController(IAuthService authService, IHttpContextAccessor httpContextAccessor)
        {
            _authService = authService;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request);

            SetRefreshTokenCookie(result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Registracija uspješna"));
        }

        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> Login([FromBody] LoginRequest request)
        {
            var ipAddress = _httpContextAccessor.HttpContext.Connection.RemoteIpAddress?.ToString();
            var result = await _authService.LoginAsync(request, ipAddress);

            if (result.RequiresTwoFactor)
            {
                return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Potrebna je 2FA verifikacija"));
            }

            SetRefreshTokenCookie(result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Prijava uspješna"));
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

            var result = await _authService.RefreshTokenAsync(completeRequest);

            SetRefreshTokenCookie(result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Token osvježen"));
        }

        [HttpPost("two-factor")]
        public async Task<ActionResult<ApiResponse<AuthResponse>>> TwoFactorVerify([FromBody] TwoFactorRequest request)
        {
            var result = await _authService.ValidateTwoFactorAsync(request);

            SetRefreshTokenCookie(result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "2FA verifikacija uspješna"));
        }

        [Authorize]
        [HttpPost("setup-2fa")]
        public async Task<ActionResult<ApiResponse<bool>>> SetupTwoFactor()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _authService.SetupTwoFactorAsync(userId);
            return Ok(ApiResponse<bool>.SuccessResponse(result, "2FA postavke uspješno omogućene"));
        }

        [Authorize]
        [HttpGet("generate-2fa-code")]
        public async Task<ActionResult<ApiResponse<string>>> GenerateTwoFactorCode()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var code = await _authService.GenerateTwoFactorCodeAsync(userId);
            return Ok(ApiResponse<string>.SuccessResponse(code, "2FA kod generiran"));
        }

        [Authorize]
        [HttpPost("verify-2fa-code")]
        public async Task<ActionResult<ApiResponse<bool>>> VerifyTwoFactorCode([FromBody] string code)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _authService.VerifyTwoFactorCodeAsync(userId, code);
            return Ok(ApiResponse<bool>.SuccessResponse(result, "2FA kod verificiran"));
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<ActionResult<ApiResponse<bool>>> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _authService.LogoutAsync(userId);

            Response.Cookies.Delete("refresh_token");

            return Ok(ApiResponse<bool>.SuccessResponse(result, "Odjava uspješna"));
        }

        [Authorize]
        [HttpGet("current-user")]
        public async Task<ActionResult<ApiResponse<CurrentUserResponse>>> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _authService.GetCurrentUserAsync(userId);

            return Ok(ApiResponse<CurrentUserResponse>.SuccessResponse(user, "Podaci o korisniku"));
        }

        private void SetRefreshTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Nije dostupan JavaScript-u - zaštita od XSS napada
                Expires = DateTime.UtcNow.AddDays(7), // 7 dana, identično postavci u JwtSettings
                Secure = true, // Samo preko HTTPS-a - zaštita od presretanja prometa
                SameSite = SameSiteMode.Strict, // Stroga CSRF zaštita - cookie se šalje samo na zahtjeve s istog site-a
                Path = "/api/auth" // Ograničeno samo na auth endpointe - minimizira površinu napada
            };

            Response.Cookies.Append("refresh_token", refreshToken, cookieOptions);
        }
    }
}
