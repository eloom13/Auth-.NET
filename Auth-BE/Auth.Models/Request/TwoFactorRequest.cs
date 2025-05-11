using System.ComponentModel.DataAnnotations;

namespace Auth.Models.Request
{
    public class TwoFactorRequest
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string TwoFactorCode { get; set; }
    }
}
