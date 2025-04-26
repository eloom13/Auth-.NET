using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.Exceptions
{
    public class ForbiddenAccessException : AppExceptions
    {
        public ForbiddenAccessException() : base("Nemate dozvolu za pristup ovom resursu.") { }
        public ForbiddenAccessException(string message) : base(message) { }
    }
}
