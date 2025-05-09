namespace Auth.Models.Exceptions
{
    public class AuthenticationException : AppExceptions
    {
        public AuthenticationException() : base("Authentication error.") { }
        public AuthenticationException(string message) : base(message) { }
    }
}
