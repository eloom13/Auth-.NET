using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.Exceptions
{
    public class ValidationException : AppExceptions
    {
        public ValidationException() : base("Jedan ili više validacijskih pravila nisu zadovoljeni.") { }
        public ValidationException(string message) : base(message) { }
    }
}
