using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Auth.Models.Entities
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Token { get; set; }

        [Required]
        public DateTime ExpiryTime { get; set; }

        [Required]
        public DateTime CreatedAt { get; set; }

        [Required]
        public string UserId { get; set; }

        [ForeignKey(nameof(UserId))]
        public User User { get; set; }

        public bool IsExpired => DateTime.UtcNow >= ExpiryTime;

        public string? ReplacedByToken { get; set; }

        public DateTime? RevokedAt { get; set; }


        // Dodatno
        public string? CreatedByIp { get; set; }
        public string? RevokedByIp { get; set; }
        public string? DeviceInfo { get; set; }
    }
}
