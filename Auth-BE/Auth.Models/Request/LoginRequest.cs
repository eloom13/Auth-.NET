using System.ComponentModel.DataAnnotations;

namespace Auth.Models.Request
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Email je obavezan")]
        [EmailAddress(ErrorMessage = "Neispravan format email adrese")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Lozinka je obavezna")]
        public string Password { get; set; }
    }
}
