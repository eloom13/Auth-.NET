using Auth.API.Extensions;
using Auth.API.Middleware;
using Auth.API.Seed;
using Auth.Services.Interfaces;
using Auth.Services.Services;
using Auth.Services.Settings;
using DotNetEnv;
using Mapster;

Env.Load();

var builder = WebApplication.CreateBuilder(args);

// === Add services ===
builder.Services.AddPersistenceServices(builder.Configuration);
builder.Services.AddIdentityServices(builder.Configuration);
builder.Services.AddInfrastructureServices(builder.Configuration);
builder.Services.AddRabbitMQServices(builder.Configuration);

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ITwoFactorService, TwoFactorService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton<IEmailService, EmailService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddMapster();

builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// U Program.cs
builder.Services.Configure<RefreshTokenSettings>(builder.Configuration.GetSection("RefreshToken"));

// Cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.LoginPath = "/api/auth/login";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.Name = "AuthProject.Cookies";
    options.SlidingExpiration = true;
});

var app = builder.Build();

// === Middlewares ===
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseHttpsRedirection();

app.UseRouting();

app.UseCors("AllowSpecificOrigin");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

await SeedData.SeedRolesAsync(app.Services.CreateScope().ServiceProvider);

app.Run();