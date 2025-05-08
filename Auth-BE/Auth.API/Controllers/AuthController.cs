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

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

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

            CookieHelper.SetRefreshTokenCookie(HttpContext, result.RefreshToken);

            result.RefreshToken = null;

            return Ok(ApiResponse<AuthResponse>.SuccessResponse(result, "Prijava uspješna"));
        }

        [Authorize]
        [HttpGet("current-user")]
        public async Task<ActionResult<ApiResponse<CurrentUserResponse>>> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _authService.GetCurrentUserAsync(userId);

            return Ok(ApiResponse<CurrentUserResponse>.SuccessResponse(user, "Podaci o korisniku"));
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
        [HttpPost("logout")]
        public async Task<ActionResult<ApiResponse<bool>>> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _authService.LogoutAsync(userId);

            Response.Cookies.Delete("refresh_token");

            return Ok(ApiResponse<bool>.SuccessResponse(result, "Odjava uspješna"));
        }
    }
}
