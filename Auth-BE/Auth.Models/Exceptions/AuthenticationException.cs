using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.Exceptions
{
    public class AuthenticationException: AppExceptions
    {
        public AuthenticationException() : base("Pogreška prilikom autentifikacije.") { }
        public AuthenticationException(string message) : base(message) { }
    }
}
