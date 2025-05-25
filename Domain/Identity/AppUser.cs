using System.ComponentModel.DataAnnotations;
using Domain.Base;

namespace Domain.Identity;

public class AppUser : BaseUser<AppUserRole>
{
    [MinLength(1), MaxLength(50)] public string FirstName { get; set; } = default!;
    [MinLength(1), MaxLength(50)] public string LastName { get; set; } = default!;
    public ICollection<AppRefreshToken>? AppRefreshTokens { get; set; }
}