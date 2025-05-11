namespace Auth.Models.DTOs
{
    public class EmailMessage
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string HtmlBody { get; set; }
    }
}
