using Auth.API.Middleware;
using Auth.Models.Data;
using Auth.Models.Entities;
using Auth.Services.Interfaces;
using Auth.Services.Services;
using Auth.Services.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    // Postavke za lozinke - osiguravaju kompleksne lozinke
    options.Password.RequireDigit = true; // Zahtijeva brojeve
    options.Password.RequireLowercase = true; // Zahtijeva mala slova
    options.Password.RequireUppercase = true; // Zahtijeva velika slova
    options.Password.RequireNonAlphanumeric = true; // Zahtijeva specijalne znakove
    options.Password.RequiredLength = 8; // Minimalna duljina 8 znakova

    // Postavke za zaklju?avanje ra?una nakon previše neuspjelih pokušaja
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); // 15 minuta zaklju?avanja
    options.Lockout.MaxFailedAccessAttempts = 5; // Nakon 5 neuspjelih pokušaja

    // Postavke za email - sprje?ava duplikate email adresa
    options.User.RequireUniqueEmail = true;

    // Postavke za 2FA - konfiguracija provider-a za dvofaktorsku autentifikaciju
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
}).AddEntityFrameworkStores<ApplicationDbContext>() // Sprema podatke o korisnicima u našu bazu
.AddDefaultTokenProviders();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
builder.Services.Configure<JWTSettings>(jwtSettings);

var secret = jwtSettings["Secret"];
var issuer = jwtSettings["Issuer"];
var audience = jwtSettings["Audience"];
var key = Encoding.ASCII.GetBytes(secret);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // U produkciji postaviti na true
    options.SaveToken = true; // Sprema token u AuthenticationProperties
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true, // Provjerava potpis
        IssuerSigningKey = new SymmetricSecurityKey(key), // Klju? za validaciju potpisa
        ValidateIssuer = true, // Provjerava izdavatelja
        ValidateAudience = true, // Provjerava publiku
        ValidIssuer = issuer, // Dozvoljeni izdavatelj
        ValidAudience = audience, // Dozvoljena publika
        ValidateLifetime = true, // Provjerava istek tokena
        ClockSkew = TimeSpan.Zero // Nema tolerancije za vremensku razliku
    };
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddHttpContextAccessor();



builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });

    // Dodavanje konfiguracije za JWT u Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        builder => builder
            .WithOrigins("http://localhost:4200") // Angular frontend
            .AllowAnyMethod() // Dozvoljava sve HTTP metode
            .AllowAnyHeader() // Dozvoljava sve HTTP headers
            .AllowCredentials()); // Dozvoljava slanje cookieja u cross-origin zahtjevima
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseHttpsRedirection();
app.UseCors("AllowSpecificOrigin");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    // Kreiranje osnovnih uloga
    string[] roleNames = { "Admin", "User" };
    foreach (var roleName in roleNames)
    {
        var roleExists = await roleManager.RoleExistsAsync(roleName);
        if (!roleExists)
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

app.Run();
