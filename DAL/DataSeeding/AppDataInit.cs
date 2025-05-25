using Domain.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DAL.DataSeeding;

public class AppDataInit
{
    public static void SeedAppData(AppDbContext context)
    {
        
    }

    public static void MigrateDatabase(AppDbContext context)
    {
        context.Database.Migrate();
    }

    public static void DeleteDatabase(AppDbContext context)
    {
        context.Database.EnsureDeleted();
    }

    public static void SeedIdentity(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
    {
        foreach (var (roleName, id) in InitialData.Roles)
        {
            var role = roleManager.FindByNameAsync(roleName).Result;
            if (role != null) continue;
            role = new AppRole()
            {
                Id = id ?? Guid.NewGuid(),
                Name = roleName,
            };

            var result = roleManager.CreateAsync(role).Result;
            if (!result.Succeeded) throw new Exception("Role creation failed.");
        }

        foreach (var userInfo in InitialData.Users)
        {
            var user = userManager.FindByEmailAsync(userInfo.email).Result;
            if (user == null)
            {
                user = new AppUser
                {
                    Id = userInfo.id ?? Guid.NewGuid(),
                    Email = userInfo.email,
                    FirstName = userInfo.firstName,
                    LastName = userInfo.lastName,
                    UserName = userInfo.email,
                };
                var result = userManager.CreateAsync(user, userInfo.password).Result;
                if (!result.Succeeded) throw new Exception($"User creation failed. {result.Errors}");
            }


            foreach (var role in userInfo.roles)
            {
                if (userManager.IsInRoleAsync(user, role).Result)
                {
                    Console.WriteLine($"User {user.Email} already has role {role}.");
                    continue;
                }
                
                var roleResult = userManager.AddToRoleAsync(user, role).Result;
                if (!roleResult.Succeeded)
                    foreach (var error in roleResult.Errors)
                        Console.WriteLine(error.Description);
                else
                    Console.WriteLine($"User {user.Email} added to role {role}.");
                    
            }
        }
    }
}