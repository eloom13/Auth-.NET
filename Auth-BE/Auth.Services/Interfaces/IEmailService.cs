namespace Auth.Services.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAsync(string to, string subject, string htmlBody);
        Task SendEmailConfirmationAsync(string email, string confirmationLink);
        Task SendPasswordResetLinkAsync(string email, string resetLink);


        // New methods that use the message queue
        void QueueEmailAsync(string to, string subject, string htmlBody);
        void QueueEmailConfirmationAsync(string email, string confirmationLink);
        void QueuePasswordResetLinkAsync(string email, string resetLink);
    }
}