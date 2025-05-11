namespace Auth.Models.Response
{
    public class CurrentUserResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public bool IsTwoFactorEnabled { get; set; }
        public bool EmailConfirmed { get; set; }
    }
}
