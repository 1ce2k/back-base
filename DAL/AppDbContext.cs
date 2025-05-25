using Domain.Base;
using Domain.Identity;
using Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace DAL;

public class AppDbContext
    : IdentityDbContext<AppUser, AppRole, Guid, IdentityUserClaim<Guid>, AppUserRole, IdentityUserLogin<Guid>,
        IdentityRoleClaim<Guid>, IdentityUserToken<Guid>>
{
    public DbSet<AppRefreshToken> AppRefreshTokens { get; set; }
    private readonly ILogger<AppDbContext> _logger;
    private readonly IUserNameResolver _userNameResolver;

    public AppDbContext(DbContextOptions<AppDbContext> options, IUserNameResolver userNameResolver,
        ILogger<AppDbContext> logger)
        : base(options)
    {
        _userNameResolver = userNameResolver;
        _logger = logger;
    }


    protected override void OnModelCreating(ModelBuilder builder)
    {
        // to save time not in UTC
        // builder.Entity<EntityName>()
        //     .Property(e => e.Date)
        //     .HasColumnType("timestamp without time zone");

        base.OnModelCreating(builder);


        foreach (var relationship in builder.Model
                     .GetEntityTypes().SelectMany(e => e.GetForeignKeys()))
            relationship.DeleteBehavior = DeleteBehavior.Restrict;

        builder.Entity<AppUserRole>()
            .HasIndex(a => new { a.UserId, a.RoleId })
            .IsUnique();

        builder.Entity<AppUserRole>()
            .HasOne(a => a.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(a => a.UserId);

        builder.Entity<AppUserRole>()
            .HasOne(a => a.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(a => a.RoleId);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken())
    {
        var addedEntries = ChangeTracker.Entries();
        foreach (var entry in addedEntries)
        {
            if (entry is { Entity: IDomainMeta })
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        (entry.Entity as IDomainMeta)!.CreatedBy = _userNameResolver.CurrentUserName;
                        (entry.Entity as IDomainMeta)!.CreatedAt = DateTime.UtcNow;
                        break;
                    case EntityState.Modified:
                        entry.Property("ChangedAt").IsModified = true;
                        entry.Property("ChangedBy").IsModified = true;
                        (entry.Entity as IDomainMeta)!.ChangedBy = _userNameResolver.CurrentUserName;
                        (entry.Entity as IDomainMeta)!.ChangedAt = DateTime.UtcNow;

                        entry.Property("CreatedAt").IsModified = false;
                        entry.Property("CreatedBy").IsModified = false;
                        break;
                }
            }

            if (entry is not { Entity: IDomainUserId, State: EntityState.Modified }) continue;
            entry.Property("UserId").IsModified = false;
            _logger.LogWarning("UserId modification attempt. Denied!");
        }

        return base.SaveChangesAsync(cancellationToken);
    }
}