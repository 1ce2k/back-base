using Microsoft.AspNetCore.Identity;

namespace Domain.Base;


public abstract class BaseUserRole<TUser, TRole> : BaseUserRole<Guid, TUser, TRole>
    where TUser : class
    where TRole : class
{
}

public abstract class BaseUserRole<TKey, TUser, TRole> : IdentityUserRole<TKey>
    where TKey : IEquatable<TKey>
    where TUser : class
    where TRole : class
{
    public TUser? User { get; set; }
    public TRole? Role { get; set; }
}
