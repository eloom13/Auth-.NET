namespace Auth.Models.Exceptions
{
    public class ConflictException : AppExceptions
    {
        public ConflictException() : base("A conflict occurred while processing the request.") { }
        public ConflictException(string message) : base(message) { }
        public ConflictException(string name, object key) : base($"Entity \"{name}\" ({key}) already exists.") { }
    }
}
