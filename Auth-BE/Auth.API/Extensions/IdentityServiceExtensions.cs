using Auth.API.Helpers;
using Auth.Models.Data;
using Auth.Models.Entities;
using Auth.Models.Exceptions;
using Auth.Models.Request;
using Auth.Services.Interfaces;
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
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;

                // User settings
                options.User.RequireUniqueEmail = true;
                //options.SignIn.RequireConfirmedEmail = true; // Require confirmed email

                // Token provider settings
                options.Tokens.EmailConfirmationTokenProvider = "Default";
                options.Tokens.PasswordResetTokenProvider = "Default";
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
                opts.ExpirationInMinutes = 15; // TESTING
                opts.RefreshTokenExpirationInDays = 7;
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
                    OnAuthenticationFailed = async context =>
                    {
                        /// Check if JWT is expired
                        if (context.Exception is SecurityTokenExpiredException)
                        {
                            var httpContext = context.HttpContext;
                            var refreshToken = httpContext.Request.Cookies["refresh_token"];

                            if (string.IsNullOrEmpty(refreshToken))
                                return;

                            try
                            {
                                var expiredToken = httpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
                                if (string.IsNullOrEmpty(expiredToken))
                                    return;

                                var authService = httpContext.RequestServices.GetRequiredService<IAuthService>();
                                var logger = httpContext.RequestServices.GetRequiredService<ILogger<JwtBearerEvents>>();

                                logger.LogInformation("Pokušavam osvježiti istekli token");

                                var refreshRequest = new RefreshTokenRequest
                                {
                                    Token = expiredToken,
                                    RefreshToken = refreshToken
                                };

                                var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                                var response = await authService.RefreshTokenAsync(refreshRequest, ipAddress);

                                CookieHelper.SetRefreshTokenCookie(httpContext, response.RefreshToken);

                                httpContext.Response.Headers.Add("X-New-Token", response.Token);

                                httpContext.Items["TokenRefreshed"] = true;
                                httpContext.Items["NewToken"] = response.Token;

                                logger.LogInformation("Token refreshed");
                            }
                            catch (Exception ex)
                            {
                                var logger = httpContext.RequestServices.GetRequiredService<ILogger<JwtBearerEvents>>();
                                logger.LogWarning(ex, "Failed refreshing token");
                            }
                        }
                    },
                    OnChallenge = context =>
                    {
                        if (context.HttpContext.Items.ContainsKey("TokenRefreshed"))
                        {
                            context.HandleResponse();

                            var response = new
                            {
                                success = true,
                                message = "Token refreshed",
                                token = context.HttpContext.Items["NewToken"] as string
                            };

                            context.HttpContext.Response.StatusCode = 200;
                            context.HttpContext.Response.ContentType = "application/json";
                            var jsonResponse = System.Text.Json.JsonSerializer.Serialize(response);
                            context.HttpContext.Response.WriteAsync(jsonResponse);

                            return Task.CompletedTask;
                        }

                        context.HandleResponse();
                        throw new AuthenticationException("You are not authorized, or token is expired.");
                    },
                    OnMessageReceived = context =>
                    {
                        var token = context.Request.Headers["Authorization"].FirstOrDefault();
                        if (!string.IsNullOrEmpty(token))
                        {
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