namespace Auth.Models.Exceptions
{
    public class ForbiddenAccessException : AppExceptions
    {
        public ForbiddenAccessException() : base("You do not have permission to access this resource.") { }
        public ForbiddenAccessException(string message) : base(message) { }
    }
}
