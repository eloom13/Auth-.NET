namespace Auth.Models.Response
{
    public class AuthResponse
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expiration { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public bool EmailNotConfirmed { get; set; }
    }
}