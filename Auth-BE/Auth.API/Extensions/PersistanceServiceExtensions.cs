using Auth.Models.Data;
using DotNetEnv;
using Microsoft.EntityFrameworkCore;

namespace Auth.API.Extensions
{
    public static class PersistenceServiceExtensions
    {
        public static IServiceCollection AddPersistenceServices(this IServiceCollection services, ConfigurationManager configuration)
        {
            var connectionString = Env.GetString("DB_CONNECTION_STRING");

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));

            return services;
        }
    }
}
