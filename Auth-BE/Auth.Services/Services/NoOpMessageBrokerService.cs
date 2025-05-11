using Auth.Services.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Services.Services
{
    public class NoOpMessageBrokerService : IMessageBrokerService
    {
        private readonly ILogger<NoOpMessageBrokerService> _logger;

        public NoOpMessageBrokerService(ILogger<NoOpMessageBrokerService> logger)
        {
            _logger = logger;
        }

        public void PublishEmailMessage(string queueName, object message)
        {
            _logger.LogWarning("RabbitMQ not available - message to {Queue} not sent", queueName);
        }

        public void StartConsuming(string queueName, Action<string> callback)
        {
            _logger.LogWarning("RabbitMQ not available - consumer for {Queue} not started", queueName);
        }
    }
}