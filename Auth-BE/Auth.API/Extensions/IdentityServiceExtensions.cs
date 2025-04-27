using Auth.Models.Data;
using Auth.Models.Entities;
using Auth.Services.Settings;
using DotNetEnv;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Auth.API.Extensions
{
    public static class IdentityServiceExtensions
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services, ConfigurationManager configuration)
        {
            services.AddIdentity<User, IdentityRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.User.RequireUniqueEmail = true;
                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            var secret = Env.GetString("JWT_SECRET");
            var issuer = Env.GetString("JWT_ISSUER");
            var audience = Env.GetString("JWT_AUDIENCE");

            services.Configure<JWTSettings>(opts =>
            {
                opts.Secret = secret;
                opts.Issuer = issuer;
                opts.Audience = audience;
                opts.ExpirationInMinutes = 60;
                opts.RefreshTokenExpirationInDays = 30;
            });

            var key = Encoding.ASCII.GetBytes(secret);


            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {


                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        throw new Auth.Models.Exceptions.AuthenticationException("Niste autorizirani ili token nije valjan.");
                    },
                    OnMessageReceived = context =>
                    {
                        var token = context.Request.Headers["Authorization"].FirstOrDefault();
                        if (!string.IsNullOrEmpty(token))
                        {
                            // Ako NE počinje sa "Bearer ", pretpostavljamo da je čisti JWT
                            if (!token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                            {
                                context.Token = token;
                            }
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            return services;
        }
    }
}
