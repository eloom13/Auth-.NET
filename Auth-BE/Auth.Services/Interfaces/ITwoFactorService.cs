namespace Auth.Services.Interfaces
{
    public interface ITwoFactorService
    {
        Task<bool> SetupTwoFactorAsync(string userId);
        //Task<string> GenerateTwoFactorCodeAsync(string userId);
        //Task<bool> VerifyTwoFactorCodeAsync(string userId, string code);
        //Task<AuthResponse> ValidateTwoFactorAsync(TwoFactorRequest request);
    }
}
