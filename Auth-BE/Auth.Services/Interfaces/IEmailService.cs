namespace Auth.Services.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);
        Task SendEmailConfirmationAsync(string email, string confirmationLink);
        Task SendPasswordResetLinkAsync(string email, string resetLink);
        Task Send2FACodeAsync(string email, string code);

        void QueueEmailAsync(string to, string subject, string htmlBody);
        void QueueEmailConfirmationAsync(string email, string confirmationLink);
        void QueuePasswordResetLinkAsync(string email, string resetLink);
        void Queue2FACodeAsync(string email, string code);
    }
}