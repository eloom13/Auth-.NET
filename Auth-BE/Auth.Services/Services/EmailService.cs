using Auth.Services.Interfaces;
using Auth.Services.Settings;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace Auth.Services.Services
{
    public class EmailService : IEmailService
    {
        private readonly SMTPSettings _smtpSettings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<SMTPSettings> smtpSettings, ILogger<EmailService> logger)
        {
            _smtpSettings = smtpSettings.Value;
            _logger = logger;
        }

        public async Task SendEmailAsync(string to, string subject, string htmlBody)
        {
            try
            {
                var message = new MailMessage
                {
                    From = new MailAddress(_smtpSettings.FromEmail, _smtpSettings.FromName),
                    Subject = subject,
                    Body = htmlBody,
                    IsBodyHtml = true
                };

                message.To.Add(new MailAddress(to));

                using var client = new SmtpClient(_smtpSettings.Host, _smtpSettings.Port)
                {
                    Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password),
                    EnableSsl = _smtpSettings.EnableSsl
                };

                await client.SendMailAsync(message);
                _logger.LogInformation("Email sent successfully to {Email}", to);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {Email}", to);
                throw;
            }
        }

        public async Task SendEmailConfirmationAsync(string email, string confirmationLink)
        {
            string subject = "Confirm Your Email Address";
            string body = $@"
                <html>
                <body>
                    <h2>Please confirm your email address</h2>
                    <p>Thank you for registering. Please confirm your email by clicking the link below:</p>
                    <p><a href='{confirmationLink}'>Confirm Email</a></p>
                    <p>If you didn't request this email, please ignore it.</p>
                </body>
                </html>";

            await SendEmailAsync(email, subject, body);
        }

        public async Task SendPasswordResetLinkAsync(string email, string resetLink)
        {
            string subject = "Password Reset";
            string body = $@"
                <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>You've requested to reset your password. Please click the link below to reset it:</p>
                    <p><a href='{resetLink}'>Reset Password</a></p>
                    <p>If you didn't request this password reset, please ignore this email and your password will remain unchanged.</p>
                </body>
                </html>";

            await SendEmailAsync(email, subject, body);
        }
    }
}