namespace Auth.Models.Exceptions
{
    public class NotFoundException : AppExceptions
    {
        public NotFoundException() : base("The requested resource was not found.") { }
        public NotFoundException(string message) : base(message) { }
        public NotFoundException(string message, params object[] args) : base(message, args) { }
        public NotFoundException(string name, object key) : base($"Entity \"{name}\" ({key}) was not found.") { }
    }
}
