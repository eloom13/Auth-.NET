using Auth.Services.Settings;
using DotNetEnv;
using Microsoft.OpenApi.Models;

namespace Auth.API.Extensions
{
    public static class InfrastructureServiceExtensions
    {
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, ConfigurationManager configuration)
        {
            // Configure SMTP
            var smtpHost = Env.GetString("SMTP_HOST");
            var smtpPort = Env.GetInt("SMTP_PORT");
            var smtpUsername = Env.GetString("SMTP_USERNAME");
            var smtpPassword = Env.GetString("SMTP_PASSWORD");
            var smtpEnableSsl = Env.GetBool("SMTP_ENABLE_SSL");
            var smtpFromEmail = Env.GetString("SMTP_FROM_EMAIL");
            var smtpFromName = Env.GetString("SMTP_FROM_NAME") ?? "Auth App";

            services.Configure<SMTPSettings>(opts =>
            {
                opts.Host = smtpHost;
                opts.Port = smtpPort;
                opts.Username = smtpUsername;
                opts.Password = smtpPassword;
                opts.EnableSsl = smtpEnableSsl;
                opts.FromEmail = smtpFromEmail;
                opts.FromName = smtpFromName;
            });

            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigin",
                    builder => builder
                        .WithOrigins("http://localhost:4200")
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials());
            });

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });

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

            return services;
        }
    }
}