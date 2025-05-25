using API.DTO.v1;
using DAL;

namespace WebApp.BackGround;

public class BackGroundTask : BackgroundService
{
    private readonly ILogger<BackGroundTask> _logger;
    private readonly IServiceScopeFactory _scopeFactory;

    public BackGroundTask(IServiceScopeFactory scopeFactory, ILogger<BackGroundTask> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using (var scope = _scopeFactory.CreateScope())
            {
                try
                {
                    // var context = scope.ServiceProvider
                    //     .GetRequiredService<AppDbContext>();
                    // Foo(context);
                    _logger.LogInformation("BackGroundTask is running.");

                }
                catch (Exception e)
                {
                    _logger.LogError(e, e.Message);
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        }
    }

    private void Foo(AppDbContext context)
    {
        // logic for background task like assigning value each X minutes/hours ...
        // for lottery where end date is > now calc tickets for each user based on activity
        // context.SaveChangesAsync();
    }
}