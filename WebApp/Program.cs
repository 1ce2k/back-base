// todo: testing (take from akaver)

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using DAL;
using DAL.DataSeeding;
using Domain.Identity;
using Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Swashbuckle.AspNetCore.SwaggerGen;
using WebApp;
using WebApp.Helpers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
                       throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

#pragma warning disable CS0618
NpgsqlConnection.GlobalTypeMapper.EnableDynamicJson();
#pragma warning restore CS0618

if (builder.Environment.IsProduction())
    builder.Services.AddDbContext<AppDbContext>(options =>
        options
            .UseNpgsql(
                connectionString,
                o => o.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery)
            )
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTrackingWithIdentityResolution)
    );
else
    builder.Services.AddDbContext<AppDbContext>(options =>
        options
            .UseNpgsql(
                connectionString,
                o => o.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery)
            )
            .ConfigureWarnings(w => w.Throw(RelationalEventId.MultipleCollectionIncludeWarning))
            .EnableDetailedErrors()
            .EnableSensitiveDataLogging()
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTrackingWithIdentityResolution)
    );

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// builder.Services.AddScoped<IAppUow, AppUow>();
// builder.Services.AddScoped<IAppBLL, AppBLL>();

builder.Services.AddIdentity<AppUser, AppRole>(o =>
        o.SignIn.RequireConfirmedAccount = false)
    .AddDefaultUI()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();


JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
builder.Services
    .AddAuthentication()
    .AddCookie(options => { options.SlidingExpiration = true; })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = builder.Configuration["JWTSecurity:Issuer"],
            ValidAudience = builder.Configuration["JWTSecurity:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JWTSecurity:Key"]!)),
            ClockSkew = TimeSpan.Zero
        };
    });


builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserNameResolver, UserNameResolver>();

var supportedCultures = builder.Configuration
    .GetSection("SupportedCultures")
    .GetChildren()
    .Select(c => new CultureInfo(c.Value!))
    .ToArray();

builder.Services.Configure<RequestLocalizationOptions>(o =>
{
    o.SupportedCultures = supportedCultures;
    o.SupportedUICultures = supportedCultures;
    o.DefaultRequestCulture =
        new RequestCulture(
            builder.Configuration["DefaultCulture"]!,
            builder.Configuration["DefaultCulture"]!);
    o.SetDefaultCulture(builder.Configuration["DefaultCulture"]!);

    o.RequestCultureProviders = new List<IRequestCultureProvider>
    {
        new QueryStringRequestCultureProvider(),
        new CookieRequestCultureProvider()
    };
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsAllowAll", policy =>
    {
        policy.AllowAnyHeader();
        policy.AllowAnyMethod();
        policy.AllowAnyOrigin();
        policy.SetIsOriginAllowed(host => true);
    });
});

var apiVersioningBuilder = builder.Services.AddApiVersioning(options =>
{
    options.ReportApiVersions = true;
    // in case of no explicit version
    options.DefaultApiVersion = new ApiVersion(1, 0);
});

apiVersioningBuilder.AddApiExplorer(options =>
{
    // add the versioned api explorer, which also adds IApiVersionDescriptionProvider service
    // note: the specified format code will format the version as "'v'major[.minor][-status]"
    options.GroupNameFormat = "'v'VVV";

    // note: this option is only necessary when versioning by url segment. the SubstitutionFormat
    // can also be used to control the format of the API version in route templates
    options.SubstituteApiVersionInUrl = true;
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddTransient<IConfigureOptions<SwaggerGenOptions>, SwaggerConf>();
builder.Services.AddSwaggerGen();

// ===============================================================
var app = builder.Build();
// ===============================================================

SetupAppData(app, app.Environment, app.Configuration);

if (app.Environment.IsDevelopment())
    app.UseMigrationsEndPoint();
else
    app.UseExceptionHandler("/Home/Error");

app.UseRequestLocalization(options: app.Services.GetService<IOptions<RequestLocalizationOptions>>()!.Value);

app.UseRouting();

app.UseCors("CorsAllowAll");

app.UseSwagger();
app.UseSwaggerUI(options =>
    {
        var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
        foreach (var description in provider.ApiVersionDescriptions)
        {
            options.SwaggerEndpoint(
                $"/swagger/{description.GroupName}/swagger.json",
                description.GroupName.ToUpperInvariant()
            );
        }
    }
);

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
        "areas",
        "{area:exists}/{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.MapControllerRoute(
        "default",
        "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.MapRazorPages()
    .WithStaticAssets();

app.Run();


// =============================

static void SetupAppData(IApplicationBuilder app, IWebHostEnvironment env, IConfiguration configuration)
{
    using var serviceScope = ((IApplicationBuilder)app).ApplicationServices
        .GetRequiredService<IServiceScopeFactory>()
        .CreateScope();
    var logger = serviceScope.ServiceProvider.GetRequiredService<ILogger<IApplicationBuilder>>();
    
    using var context = serviceScope.ServiceProvider.GetRequiredService<AppDbContext>();

    WaitDbConnection(context, logger);

    using UserManager<AppUser> userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
    using RoleManager<AppRole> roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<AppRole>>();

    if (context.Database.ProviderName!.Contains("InMemory"))
    {
        context.Database.EnsureCreated();
        context.Database.EnsureCreated();
        return;
    }

    if (configuration.GetValue<bool>("DataInitialization:DropDatabase"))
    {
        logger.LogWarning("DropDatabase");
        AppDataInit.DeleteDatabase(context);
    }
    
    if (configuration.GetValue<bool>("DataInitialization:MigrateDatabase"))
    {
        logger.LogWarning("MigrateDatabase");
        AppDataInit.MigrateDatabase(context);
    }
    
    if (configuration.GetValue<bool>("DataInitialization:SeedIdentity"))
    {
        logger.LogWarning("SeedIdentity");
        AppDataInit.SeedIdentity(userManager, roleManager);
    }
    if (configuration.GetValue<bool>("DataInitialization:SeedData"))
    {
        logger.LogWarning("SeedData");
        AppDataInit.SeedAppData(context);
    }
}

static void WaitDbConnection(AppDbContext ctx, ILogger<IApplicationBuilder> logger)
{
    while (true)
    {
        try
        {
            ctx.Database.OpenConnection();
            ctx.Database.CloseConnection();
            return;
        }
        catch (Npgsql.NpgsqlException e)
        {
            logger.LogWarning("Checked postgres db connection. Got: {}", e.Message);

            if (e.Message.Contains("does not exist"))
            {
                logger.LogWarning("Applying migration, probably db not there (but server is)");
                return;
            }
            
            logger.LogWarning("Waiting for db connection. Sleeping 1 sec...");
            Thread.Sleep(1000);
        }
    }
}