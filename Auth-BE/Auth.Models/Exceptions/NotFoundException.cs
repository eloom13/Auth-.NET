using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.Exceptions
{
    public class NotFoundException: AppExceptions
    {
        public NotFoundException() : base("Traženi resurs nije pronađen.") { }
        public NotFoundException(string message) : base(message) { }
        public NotFoundException(string message, params object[] args) : base(message, args) { }
        public NotFoundException(string name, object key) : base($"Entitet \"{name}\" ({key}) nije pronađen.") { }
    }
}
