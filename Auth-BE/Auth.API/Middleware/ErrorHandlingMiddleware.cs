using Auth.Models.Exceptions;
using Auth.Models.Response;
using System.Net;
using System.Text.Json;

namespace Auth.API.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger, IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            HttpStatusCode code = HttpStatusCode.InternalServerError;
            ApiResponse<object> errorResponse;

            if (exception is AppExceptions appException)
            {
                _logger.LogWarning("Application error: {Message}", appException.Message);

                code = exception switch
                {
                    NotFoundException => HttpStatusCode.NotFound,
                    ValidationException => HttpStatusCode.BadRequest,
                    ForbiddenAccessException => HttpStatusCode.Forbidden,
                    AuthenticationException => HttpStatusCode.Unauthorized,
                    ConflictException => HttpStatusCode.Conflict,
                    SecurityException => HttpStatusCode.Unauthorized,
                    _ => HttpStatusCode.InternalServerError
                };

                errorResponse = ApiResponse<object>.ErrorResponse(appException.Message, null, (int)code);
            }
            else
            {
                _logger.LogError("Unexpected error: {Message}", exception.Message);

                errorResponse = _environment.IsDevelopment()
                    ? ApiResponse<object>.ErrorResponse(
                        $"An unexpected error occurred: {exception.Message}",
                        new List<string> { exception.StackTrace },
                        (int)code)
                    : ApiResponse<object>.ErrorResponse(
                        "An unexpected error occurred. Please try again or contact the administrator.",
                        null,
                        (int)code);
            }

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)code;

            var result = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await context.Response.WriteAsync(result);
        }

    }
}
