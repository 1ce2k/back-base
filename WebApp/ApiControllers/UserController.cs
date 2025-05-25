using System.Security.Claims;
using API.DTO.v1;
using Asp.Versioning;
using DAL;
using Domain.Identity;
using Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace WebApp.ApiControllers;

[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]/[action]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly AppDbContext _context;

    public UserController(UserManager<AppUser> userManager, AppDbContext context)
    {
        _userManager = userManager;
        _context = context;
    }

    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<User>>> GetUsers()
    {
        var users = await _context.Users.ToListAsync();
        var res = users.Select(e => new User
        {
            Id = e.Id,
            FirstName = e.FirstName,
            LastName = e.LastName,
            Email = e.Email!,
        });
        return Ok(res);
    }

    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User,Admin")]
    [HttpGet("{id}")]
    public async Task<ActionResult<IEnumerable<User>>> GetUser([FromRoute] Guid id)
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var userId = User.GetUserId();

        if (role != "Admin" && userId != id)
        {
            return Forbid();
        }

        var user = await _context.Users.Where(e => e.Id == id).Select(e => Map(e)).FirstOrDefaultAsync();
        return Ok(user);
    }

    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User,Admin")]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<User>>> Me()
    {
        var userId = User.GetUserId();
        var dbUser = await _context.Users.FirstAsync(e => e.Id == userId);
        return Ok(Map(dbUser));
    }

    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "User,Admin")]
    [HttpPut("{id}")]
    public async Task<ActionResult<IEnumerable<User>>> UpdateUser([FromRoute] Guid id, [FromBody] User user)
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var userId = User.GetUserId();

        if (role != "Admin" && userId != id)
        {
            return Forbid();
        }

        var dbUser = await _context.Users.FirstAsync(e => e.Id == id);
        dbUser.FirstName = user.FirstName;
        dbUser.LastName = user.LastName;
        dbUser.Email = user.Email;
        _context.Users.Update(dbUser);
        await _context.SaveChangesAsync();
        return Ok(Map(dbUser));
    }


    [Produces("application/json")]
    [Consumes("application/json")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
    [HttpPatch("{id}")]
    public async Task<ActionResult> ChangeUserRole([FromRoute] Guid id, [FromBody] string newRole)
    {
        var user = await _userManager.FindByIdAsync(id.ToString());
        if (user == null)
        {
            return NotFound($"User with ID {id} not found.");
        }

        var currentRoles = await _userManager.GetRolesAsync(user);

        // Remove all current roles
        var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
        if (!removeResult.Succeeded)
        {
            return BadRequest("Failed to remove existing roles.");
        }

        // Add new role
        var addResult = await _userManager.AddToRoleAsync(user, newRole);
        if (!addResult.Succeeded)
        {
            return BadRequest("Failed to assign new role.");
        }

        return Ok($"User role updated to '{newRole}'.");
    }


    private static User? Map(AppUser? user)
    {
        if (user == null) return null;
        return new User
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email!,
        };
    }
}