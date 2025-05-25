namespace API.DTO.v1.Identity;

public class RegisterModel
{
    public string Email { get; set; } = default!;
    public string Password { get; set; } = default!;
    public string Firstname { get; set; } = default!;
    public string Lastname { get; set; } = default!;
}