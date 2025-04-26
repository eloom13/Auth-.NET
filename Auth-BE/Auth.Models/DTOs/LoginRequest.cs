using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.DTOs
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
