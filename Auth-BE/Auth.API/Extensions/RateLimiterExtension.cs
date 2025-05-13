// Auth.API/Extensions/RateLimiterExtensions.cs
using System.Threading.RateLimiting;

namespace Auth.API.Extensions
{
    public static class RateLimiterExtensions
    {
        public static IServiceCollection AddAppRateLimiter(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddRateLimiter(options =>
            {
                options.AddPolicy("auth", httpContext =>
                {
                    var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: ipAddress,
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 5,
                            Window = TimeSpan.FromMinutes(1),
                            AutoReplenishment = true
                        });
                });

                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
                {
                    var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: ipAddress,
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1000,
                            Window = TimeSpan.FromHours(1),
                            AutoReplenishment = true
                        });
                });

                options.OnRejected = async (context, token) =>
                {
                    context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    context.HttpContext.Response.ContentType = "application/json";

                    TimeSpan? retryAfter = null;
                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var timeSpan))
                    {
                        retryAfter = timeSpan;
                    }

                    var response = new
                    {
                        success = false,
                        message = "Too many requests. Please try again later.",
                        retryAfter = retryAfter?.TotalSeconds ?? 60
                    };

                    if (retryAfter.HasValue)
                    {
                        context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.Value.TotalSeconds).ToString();
                    }

                    await context.HttpContext.Response.WriteAsJsonAsync(response, token);
                };
            });

            return services;
        }
    }
}