namespace Auth.Models.Response
{
    public class RegisterResponse
    {
        public string UserId { get; set; }
        public string Email { get; set; }
        public bool RequiresEmailConfirmation { get; set; }
        public string Token { get; set; }
        public DateTime? Expiration { get; set; }
    }
}