using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.DTOs
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "Email je obavezan")]
        [EmailAddress(ErrorMessage = "Neispravan format email adrese")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Lozinka je obavezna")]
        [MinLength(8, ErrorMessage = "Lozinka mora sadržavati najmanje 8 znakova")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Potvrda lozinke je obavezna")]
        [Compare("Password", ErrorMessage = "Lozinka i potvrda se ne podudaraju")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Ime je obavezno")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Prezime je obavezno")]
        public string LastName { get; set; }
    }
}
