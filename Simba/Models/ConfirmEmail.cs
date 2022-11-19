using System.ComponentModel.DataAnnotations;

namespace Simba.Models
{
    public class ConfirmEmail
    {
        [Required]
        public string Token { get; set; }
        [Required]
        public string UserId { get; set; }
    }

    public class UserEmail
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
