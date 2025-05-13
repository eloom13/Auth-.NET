namespace Auth.Services.Settings
{
    public class RefreshTokenSettings
    {
        public int ExpirationInDays { get; set; }
        public int MaxRefreshCount { get; set; }
        public int MaxActiveSessionsPerUser { get; set; }
        public bool EnableTokenRotation { get; set; }
        public bool DetectTokenReuse { get; set; }
    }
}