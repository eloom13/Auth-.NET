namespace Auth.API.Helpers
{
    public static class CookieHelper
    {
        public static void SetRefreshTokenCookie(HttpContext context, string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Nije dostupan JavaScript-u - zaštita od XSS napada
                Expires = DateTime.UtcNow.AddDays(7), // 7 dana, identično postavci u JwtSettings
                Secure = true, // Samo preko HTTPS-a - zaštita od presretanja prometa
                SameSite = SameSiteMode.Strict, // Stroga CSRF zaštita - cookie se šalje samo na zahtjeve s istog site-a
                Path = "/api/auth" // Ograničeno samo na auth endpointe - minimizira površinu napada
            };

            context.Response.Cookies.Append("refresh_token", refreshToken, cookieOptions);
        }
    }
}
