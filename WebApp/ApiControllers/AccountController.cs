using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using API.DTO.v1;
using API.DTO.v1.Identity;
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

/// <summary>
/// User Account controller - login register etc
/// </summary>
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]/[action]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly Random _random = new Random();
    private readonly UserManager<AppUser> _userManager;
    private readonly ILogger<AccountController> _logger;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _context;

    private const string UserPassProblem = "User/Password problem";
    private const int RandomDelayMin = 500;
    private const int RandomDelayMax = 5000;

    private const string SettingsJWTPrefix = "JWTSecurity";
    private const string SettingsJWTKey = SettingsJWTPrefix + ":Key";
    private const string SettingsJWTIssuer = SettingsJWTPrefix + ":Issuer";
    private const string SettingsJWTAudience = SettingsJWTPrefix + ":Audience";
    private const string SettingsJWTExpiresInSeconds = SettingsJWTPrefix + ":ExpiresInSeconds";
    private const string SettingsJWTRefreshTokenExpiresInSeconds = SettingsJWTPrefix + ":RefreshTokenExpiresInSeconds";


    /// <summary>
    /// Constructor
    /// </summary>
    public AccountController(IConfiguration configuration, UserManager<AppUser> userManager,
        SignInManager<AppUser> signInManager, ILogger<AccountController> logger, AppDbContext context)
    {
        _configuration = configuration;
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _context = context;
    }

    /// <summary>
    /// User authentication, returns JWT and refresh token
    /// </summary>
    /// <param name="loginInfo">Login model</param>
    /// <returns>JWT and refresh token</returns>
    [Produces("application/json")]
    [Consumes("application/json")]
    [ProducesResponseType(typeof(JWTResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Message), StatusCodes.Status404NotFound)]
    [HttpPost]
    public async Task<ActionResult<JWTResponse>> Login(
        [FromBody] LoginInfo loginInfo
    )
    {
        // verify user
        var appUser = await _userManager.FindByEmailAsync(loginInfo.Email);
        if (appUser == null)
        {
            _logger.LogWarning("WebApi login failed, email {} not found", loginInfo.Email);
            await Task.Delay(_random.Next(RandomDelayMin, RandomDelayMax));
            return NotFound(new Message(UserPassProblem));
        }

        // verify password
        var result = await _signInManager.CheckPasswordSignInAsync(appUser, loginInfo.Password, false);
        if (!result.Succeeded)
        {
            _logger.LogWarning("WebApi login failed, password {} for email {} was wrong", loginInfo.Password,
                loginInfo.Email);
            await Task.Delay(_random.Next(RandomDelayMin, RandomDelayMax));
            return NotFound(new Message(UserPassProblem));
        }
        
        await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.GivenName, appUser.FirstName));
        await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.Surname, appUser.LastName));

        var claimsPrincipal = await _signInManager.CreateUserPrincipalAsync(appUser);
        if (!_context.Database.ProviderName!.Contains("InMemory"))
        {
            var deletedRows = await _context
                .AppRefreshTokens
                .Where(t => t.UserId == appUser.Id && t.ExpirationDate < DateTime.UtcNow)
                .ExecuteDeleteAsync();
            _logger.LogInformation("Deleted {} refresh tokens", deletedRows);
        }
        else
        {
            //TODO: inMemory delete for testing
        }

        var refreshToken = new AppRefreshToken()
        {
            UserId = appUser.Id,
            ExpirationDate = GetExpirationDateTime(loginInfo.RefreshTokenExpiresInSeconds, SettingsJWTRefreshTokenExpiresInSeconds)
        };
        
        
        _context.AppRefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();


        var jwt = IdentityExtensions.GenerateJwtToken(
            claimsPrincipal.Claims,
            _configuration.GetValue<string>(SettingsJWTKey)!,
            _configuration.GetValue<string>(SettingsJWTIssuer)!,
            _configuration.GetValue<string>(SettingsJWTAudience)!,
            GetExpirationDateTime(loginInfo.JWTExpiresInSeconds, SettingsJWTExpiresInSeconds)
        );

        var responseData = new JWTResponse()
        {
            Jwt = jwt,
            RefreshToken = refreshToken.RefreshToken
        };

        return Ok(responseData);
    }

    /// <summary>
    /// Register new user, returns JWT and refresh token
    /// </summary>
    /// <param name="registerModelModel">Reg info</param>
    /// <param name="jwtExpiresInSeconds">Optional custom jwt expiration</param>
    /// <param name="refreshTokenExpiresInSeconds">Optional custom refresh token expiration</param>
    /// <returns></returns>
    [Produces("application/json")]
    [Consumes("application/json")]
    [ProducesResponseType(typeof(JWTResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Message), StatusCodes.Status400BadRequest)]
    [HttpPost]
    public async Task<ActionResult<JWTResponse>> Register(
        [FromBody] RegisterModel registerModelModel,
        [FromQuery] int? jwtExpiresInSeconds,
        [FromQuery] int? refreshTokenExpiresInSeconds
    )
    {
        var appUser = await _userManager.FindByEmailAsync(registerModelModel.Email);
        if (appUser != null)
        {
            _logger.LogWarning(" User {User} already registered", registerModelModel.Email);
            return BadRequest(new Message("User already registered"));
        }

        var refreshToken = new AppRefreshToken()
        {
            ExpirationDate = GetExpirationDateTime(refreshTokenExpiresInSeconds, SettingsJWTRefreshTokenExpiresInSeconds)
        };

        appUser = new AppUser()
        {
            Email = registerModelModel.Email,
            UserName = registerModelModel.Email,
            FirstName = registerModelModel.Firstname,
            LastName = registerModelModel.Lastname,

            AppRefreshTokens = new List<AppRefreshToken>()
            {
                refreshToken
            }
        };
        
        var result = await _userManager.CreateAsync(appUser, registerModelModel.Password);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} created a new account with password", appUser.Email);
            
            var roleResult = await _userManager.AddToRoleAsync(appUser, "User");
            if (!roleResult.Succeeded)
            {
                return BadRequest(new Message
                {
                    Messages = roleResult.Errors.Select(e => e.Description).ToList()
                });
            }

            await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.GivenName, appUser.FirstName));
            await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.Surname, appUser.LastName));
            await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.Role, "User"));

            var claimsPrincipal = await _signInManager.CreateUserPrincipalAsync(appUser);
            var jwt = IdentityExtensions.GenerateJwtToken(
                claimsPrincipal.Claims,
                _configuration.GetValue<string>(SettingsJWTKey)!,
                _configuration.GetValue<string>(SettingsJWTIssuer)!,
                _configuration.GetValue<string>(SettingsJWTAudience)!,
                GetExpirationDateTime(jwtExpiresInSeconds, SettingsJWTExpiresInSeconds)
            );
            _logger.LogInformation("WebApi login. User {User}", registerModelModel.Email);
            return Ok(new JWTResponse()
            {
                Jwt = jwt,
                RefreshToken = refreshToken.RefreshToken,
            });
        }

        var errors = result.Errors.Select(error => error.Description).ToList();
        return BadRequest(new Message() { Messages = errors });
    }

    /// <summary>
    /// Renew JWT using refresh token
    /// </summary>
    /// <param name="refreshTokenModel">Data for renewal</param>
    /// <param name="jwtExpiresInSeconds">Optional custom expiration for jwt</param>
    /// <param name="refreshTokenExpiresInSeconds">Optional custom expiration for refresh token</param>
    /// <returns></returns>
    [Produces("application/json")]
    [Consumes("application/json")]
    [ProducesResponseType(typeof(JWTResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(Message), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    [HttpPost]
    public async Task<ActionResult<JWTResponse>> RenewRefreshToken(
        [FromBody] RefreshTokenModel refreshTokenModel,
        [FromQuery] int? jwtExpiresInSeconds,
        [FromQuery] int? refreshTokenExpiresInSeconds
    )
    {
        JwtSecurityToken jwtToken;
        // get user info from jwt
        try
        {
            jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(refreshTokenModel.Jwt);
            if (jwtToken == null)
            {
                return BadRequest(new Message("No token"));
            }
        }
        catch (Exception e)
        {
            return BadRequest(new Message($"Cant parse the token, {e.Message}"));
        }

        // validate jwt, ignore expiration date
        if (!IdentityExtensions.ValidateToken(
                refreshTokenModel.Jwt,
                _configuration.GetValue<string>(SettingsJWTKey)!,
                _configuration.GetValue<string>(SettingsJWTIssuer)!,
                _configuration.GetValue<string>(SettingsJWTAudience)!
            ))
        {
            return BadRequest("JWT validation fail");
        }

        var userEmail = jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
        if (userEmail == null)
        {
            return BadRequest(new Message("No email in jwt"));
        }

        // get user and tokens
        var appUser = await _userManager.FindByEmailAsync(userEmail);
        if (appUser == null)
        {
            return NotFound($"User with email {userEmail} not found");
        }

        await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.GivenName, appUser.FirstName));
        await _userManager.AddClaimAsync(appUser, new Claim(ClaimTypes.Surname, appUser.LastName));


        // load and compare refresh tokens

        await _context.Entry(appUser).Collection(u => u.AppRefreshTokens!)
            .Query()
            .Where(x =>
                (x.RefreshToken == refreshTokenModel.RefreshToken && x.ExpirationDate > DateTime.UtcNow) ||
                (x.PreviosRefreshToken == refreshTokenModel.RefreshToken &&
                 x.PreviousExpirationDate > DateTime.UtcNow)
            )
            .ToListAsync();

        if (appUser.AppRefreshTokens == null)
        {
            return Problem("RefreshTokens collection is null");
        }

        if (appUser.AppRefreshTokens.Count == 0)
        {
            return Problem("RefreshTokens collection is empty, no valid refresh tokens found");
        }

        if (appUser.AppRefreshTokens.Count != 1)
        {
            return Problem("More than one valid refresh token found.");
        }

        // generate new jwt

        // get claims based user
        var claimsPrincipal = await _signInManager.CreateUserPrincipalAsync(appUser);

        // generate jwt
        var jwt = IdentityExtensions.GenerateJwtToken(
            claimsPrincipal.Claims,
            _configuration.GetValue<string>(SettingsJWTKey)!,
            _configuration.GetValue<string>(SettingsJWTIssuer)!,
            _configuration.GetValue<string>(SettingsJWTAudience)!,
            GetExpirationDateTime(jwtExpiresInSeconds, SettingsJWTExpiresInSeconds)
        );
        
        // make new refresh token, obsolete old ones
        var refreshToken = appUser.AppRefreshTokens.First();
        if (refreshToken.RefreshToken == refreshTokenModel.RefreshToken)
        {
            refreshToken.PreviosRefreshToken = refreshToken.RefreshToken;
            refreshToken.PreviousExpirationDate = DateTime.UtcNow.AddMinutes(1);

            refreshToken.RefreshToken = Guid.NewGuid().ToString();
            refreshToken.ExpirationDate =
                GetExpirationDateTime(refreshTokenExpiresInSeconds, SettingsJWTRefreshTokenExpiresInSeconds);
            await _context.SaveChangesAsync();
        }

        var res = new JWTResponse()
        {
            Jwt = jwt,
            RefreshToken = refreshToken.RefreshToken,
        };

        return Ok(res);
    }

    /// <summary>
    /// User Logout
    /// </summary>
    /// <param name="logout"></param>
    /// <returns></returns>
    [Produces("application/json")]
    [Consumes("application/json")]
    [ProducesResponseType(typeof(Message), StatusCodes.Status404NotFound)]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost]
    public async Task<ActionResult> Logout([FromBody] LogoutInfo logout)
    {
        // delete the refresh token - so user is kicked out after jwt expiration
        // We do not invalidate the jwt on serverside - that would require pipeline modification and checking against db on every request
        // so client can actually continue to use the jwt until it expires (keep the jwt expiration time short ~1 min)

        var appUser = await _context.Users
            .Where(u => u.Id == User.GetUserId())
            .SingleOrDefaultAsync();
        if (appUser == null)
        {
            return NotFound(
                new Message(UserPassProblem)
            );
        }
        
        var tokens =  await _context.AppRefreshTokens
            .Where(x => x.UserId == appUser.Id &&
                        ((x.RefreshToken == logout.RefreshToken) ||
                         (x.PreviosRefreshToken == logout.RefreshToken))
            )
            .ToListAsync();
        
        foreach (var appRefreshToken in tokens)
        {
            _context.AppRefreshTokens.Remove(appRefreshToken);
        }

        var deleteCount = await _context.SaveChangesAsync();

        return Ok(new { TokenDeleteCount = deleteCount });
    }

    private DateTime GetExpirationDateTime(int? expiresInSeconds, string settingsKey)
    {
        if (expiresInSeconds <= 0) expiresInSeconds = int.MaxValue;
        expiresInSeconds = expiresInSeconds < _configuration.GetValue<int>(settingsKey)
            ? expiresInSeconds
            : _configuration.GetValue<int>(settingsKey);

        return DateTime.UtcNow.AddSeconds(expiresInSeconds ?? 60);
    }
}

