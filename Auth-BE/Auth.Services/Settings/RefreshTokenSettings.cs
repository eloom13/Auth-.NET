namespace Auth.Services.Settings
{
    public class RefreshTokenSettings
    {
        public int ExpirationInDays { get; set; } = 7;
        public int MaxRefreshCount { get; set; } = 100;
        public int MaxActiveSessionsPerUser { get; set; } = 5;
        public bool EnableTokenRotation { get; set; } = true;
        public bool DetectTokenReuse { get; set; } = true;
    }
}