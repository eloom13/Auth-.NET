namespace Auth.Models.Exceptions
{
    public class ValidationException : AppExceptions
    {
        public ValidationException() : base("One or more validation rules were not met.") { }
        public ValidationException(string message) : base(message) { }
    }
}
