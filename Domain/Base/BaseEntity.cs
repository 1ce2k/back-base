namespace Domain.Base;

public abstract class BaseEntity : BaseEntity<Guid>, IDomainId
{
}

public class BaseEntity<TKey> : IDomainId<TKey>, IDomainMeta
    where TKey : IEquatable<TKey>
{
    public TKey Id { get; set; } = default!;
    public string? CreatedBy { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? ChangedBy { get; set; }
    public DateTime? ChangedAt { get; set; }
}