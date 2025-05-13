namespace Auth.Models.Exceptions
{
    public class SecurityException : AppExceptions
    {
        public SecurityException() : base("A security violation has been detected.") { }
        public SecurityException(string message) : base(message) { }
    }
}