using Auth.Services.Interfaces;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using System.Text;
using System.Text.Json;

namespace Auth.Services.Services
{
    public class RabbitMQService : IMessageBrokerService, IDisposable
    {
        private readonly string _hostName;
        private readonly string _username;
        private readonly string _password;
        private readonly int _port;
        private readonly ILogger<RabbitMQService> _logger;

        private IConnection? _connection;
        private IModel? _channel;
        private bool _isInitialized = false;
        private readonly object _lockObject = new object();

        public RabbitMQService(
            string hostName,
            string username,
            string password,
            int port,
            ILogger<RabbitMQService> logger)
        {
            _hostName = hostName;
            _username = username;
            _password = password;
            _port = port;
            _logger = logger;

            // We'll initialize the connection lazily on first use
            _logger.LogInformation("RabbitMQ service created with settings: Host={Host}, Port={Port}, Username={Username}",
                hostName, port, username);
        }

        private void EnsureConnected()
        {
            if (_isInitialized && _connection?.IsOpen == true)
                return;

            lock (_lockObject)
            {
                if (_isInitialized && _connection?.IsOpen == true)
                    return;

                try
                {
                    _logger.LogInformation("Connecting to RabbitMQ at {Host}:{Port}", _hostName, _port);

                    var factory = new ConnectionFactory
                    {
                        HostName = _hostName,
                        Port = _port,
                        UserName = _username,
                        Password = _password,
                        // Add timeout to avoid long hangs
                        RequestedConnectionTimeout = TimeSpan.FromSeconds(3)
                    };

                    _connection = factory.CreateConnection();
                    _channel = _connection.CreateModel();
                    _isInitialized = true;

                    _logger.LogInformation("Successfully connected to RabbitMQ");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to connect to RabbitMQ. Email queuing will not work.");
                    throw;
                }
            }
        }

        public void PublishEmailMessage(string queueName, object message)
        {
            try
            {
                EnsureConnected();

                if (_channel == null)
                {
                    _logger.LogWarning("Cannot publish message - no RabbitMQ connection available");
                    return;
                }

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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error publishing message to queue {QueueName}", queueName);
                // Don't rethrow - we want to fail gracefully if RabbitMQ is down
            }
        }

        public void StartConsuming(string queueName, Action<string> callback)
        {
            try
            {
                EnsureConnected();

                if (_channel == null)
                {
                    _logger.LogWarning("Cannot start consumer - no RabbitMQ connection available");
                    return;
                }

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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting consumer for queue {QueueName}", queueName);
                // Don't rethrow - we want to fail gracefully if RabbitMQ is down
            }
        }

        public void Dispose()
        {
            _channel?.Close();
            _connection?.Close();
            _logger.LogInformation("RabbitMQ connection closed");
        }
    }
}