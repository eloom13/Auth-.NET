using Auth.Services.Interfaces;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using RabbitMQ.Client.Events; // Add this import for EventingBasicConsumer
using System.Text;
using System.Text.Json;

namespace Auth.Services.Services
{
    public class RabbitMQService : IMessageBrokerService, IDisposable
    {
        private readonly IConnection _connection;
        private readonly RabbitMQ.Client.IModel _channel;
        private readonly ILogger<RabbitMQService> _logger;

        public RabbitMQService(string hostName, ILogger<RabbitMQService> logger)
        {
            _logger = logger;

            var factory = new ConnectionFactory { HostName = hostName };
            try
            {
                _connection = factory.CreateConnection();
                _channel = _connection.CreateModel(); // Fixed syntax error here
                _logger.LogInformation("Connected to RabbitMQ");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to RabbitMQ");
                throw;
            }
        }

        public void PublishEmailMessage(string queueName, object message)
        {
            _channel.QueueDeclare(
                queue: queueName,
                durable: true,
                exclusive: false,
                autoDelete: false,
                arguments: null);

            var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message));

            _channel.BasicPublish(
                exchange: "",
                routingKey: queueName,
                basicProperties: null,
                body: body);

            _logger.LogInformation("Message published to queue {QueueName}", queueName);
        }

        public void StartConsuming(string queueName, Action<string> callback)
        {
            _channel.QueueDeclare(
                queue: queueName,
                durable: true,
                exclusive: false,
                autoDelete: false,
                arguments: null);

            var consumer = new EventingBasicConsumer(_channel);
            consumer.Received += (model, ea) =>
            {
                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);

                try
                {
                    callback(message);
                    _channel.BasicAck(deliveryTag: ea.DeliveryTag, multiple: false);
                    _logger.LogInformation("Message processed from queue {QueueName}", queueName);
                }
                catch (Exception ex)
                {
                    _channel.BasicNack(deliveryTag: ea.DeliveryTag, multiple: false, requeue: true);
                    _logger.LogError(ex, "Error processing message from queue {QueueName}", queueName);
                }
            };

            _channel.BasicConsume(
                queue: queueName,
                autoAck: false,
                consumer: consumer);

            _logger.LogInformation("Started consuming from queue {QueueName}", queueName);
        }

        public void Dispose()
        {
            _channel?.Close();
            _connection?.Close();
            _logger.LogInformation("RabbitMQ connection closed");
        }
    }
}