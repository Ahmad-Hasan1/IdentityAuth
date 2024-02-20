using System.ComponentModel.DataAnnotations;

namespace IdentityAuth.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        // Add any other properties that you might need for user confirmation after external login
    }
}
