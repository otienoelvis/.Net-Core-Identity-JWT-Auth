using Microsoft.AspNetCore.Identity;

namespace Simba.Authentication
{
    public class ApplicationUser: IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

    }
}
