namespace Domain.Base.Identity;

public class BaseRefreshToken : BaseEntity<Guid>
{
    public string RefreshToken { get; set; } = Guid.NewGuid().ToString();
    public DateTime ExpirationDate { get; set; } = DateTime.UtcNow.AddDays(30);
    public string? PreviosRefreshToken { get; set; }
    public DateTime? PreviousExpirationDate { get; set; }
}