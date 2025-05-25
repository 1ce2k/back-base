using Microsoft.AspNetCore.Identity;

namespace Domain.Base.Identity;

public abstract class BaseRole<TUserRole> : BaseRole<Guid, TUserRole>
    where TUserRole : class
{
}


public abstract class BaseRole<TKey, TUserRole> : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
    where TUserRole : class
{
    public ICollection<TUserRole>? UserRoles { get; set; }
}
