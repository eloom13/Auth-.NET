namespace Auth.Services.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);
        Task SendEmailConfirmationAsync(string email, string confirmationLink);
        Task SendPasswordResetLinkAsync(string email, string resetLink);
    }
}