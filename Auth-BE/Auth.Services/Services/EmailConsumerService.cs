using Auth.Models.DTOs;
using Auth.Services.Interfaces;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace Auth.Services.Services
{
    public class EmailConsumerService : BackgroundService
    {
        private readonly IMessageBrokerService _messageBroker;
        private readonly IEmailService _emailService;
        private readonly ILogger<EmailConsumerService> _logger;
        private const string EmailQueue = "email_queue";
        private const string ConfirmationEmailQueue = "confirmation_email_queue";

        public EmailConsumerService(
            IMessageBrokerService messageBroker,
            IEmailService emailService,
            ILogger<EmailConsumerService> logger)
        {
            _messageBroker = messageBroker;
            _emailService = emailService;
            _logger = logger;
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _messageBroker.StartConsuming(EmailQueue, async (message) =>
            {
                var emailMessage = JsonSerializer.Deserialize<EmailMessage>(message);
                await _emailService.SendEmailAsync(
                    emailMessage.To,
                    emailMessage.Subject,
                    emailMessage.HtmlBody);
            });

            _messageBroker.StartConsuming(ConfirmationEmailQueue, async (message) =>
            {
                var confirmationMessage = JsonSerializer.Deserialize<EmailConfirmationMessage>(message);
                await _emailService.SendEmailConfirmationAsync(
                    confirmationMessage.Email,
                    confirmationMessage.ConfirmationLink);
            });

            return Task.CompletedTask;
        }
    }
}