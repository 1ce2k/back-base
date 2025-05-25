namespace Domain.Base;

public interface IDomainId : IDomainId<Guid>;
public interface IDomainId<TKey>
where TKey : IEquatable<TKey>
{
    public TKey Id { get; set; }
}