namespace API.DTO.v1.Identity;

public class LoginInfo
{
    public string Email { get; set; } = default!;
    public string Password { get; set; } = default!;
    public int RefreshTokenExpiresInSeconds { get; set; }
    public int JWTExpiresInSeconds { get; set; }
}