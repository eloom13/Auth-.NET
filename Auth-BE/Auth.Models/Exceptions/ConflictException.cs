using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models.Exceptions
{
    public class ConflictException : AppExceptions
    {
        public ConflictException() : base("Došlo je do konflikta pri obradi zahtjeva.") { }
        public ConflictException(string message) : base(message) { }
        public ConflictException(string name, object key) : base($"Entitet \"{name}\" ({key}) već postoji.") { }
    }
}
