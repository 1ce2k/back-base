using Microsoft.AspNetCore.Identity;

namespace Domain.Base;

public abstract class BaseUser<TUserRole> : BaseUser<Guid, TUserRole>
where TUserRole: class
{
}

public class BaseUser<TKey, TUserRole> : IdentityUser<TKey>
    where TUserRole : class
    where TKey : IEquatable<TKey>
{
    public ICollection<TUserRole>? UserRoles { get; set; }
}