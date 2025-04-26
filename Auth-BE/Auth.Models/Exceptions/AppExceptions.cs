using System.Globalization;

namespace Auth.Models.Exceptions
{
    public class AppExceptions : Exception
    {
        public AppExceptions() : base() { }

        public AppExceptions(string message) : base(message) { }

        public AppExceptions(string message, params object[] args)
            : base(string.Format(CultureInfo.CurrentCulture, message, args)) { }
    }
}
