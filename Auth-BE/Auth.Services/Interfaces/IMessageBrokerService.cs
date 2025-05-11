namespace Auth.Services.Interfaces
{
    public interface IMessageBrokerService
    {
        void PublishEmailMessage(string queueName, object message);
        void StartConsuming(string queueName, Action<string> callback);
    }
}
