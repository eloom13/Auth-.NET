using Auth.Models.Exceptions;
using Auth.Models.Response;
using System.Net;
using System.Text.Json;

namespace Auth.API.Middleware
{
    /// Middleware koji hvata sve neuhvaćene iznimke u aplikaciji i pretvara ih u strukturirane API odgovore
    /// Osigurava da klijent uvijek dobije konzistentan format odgovora čak i kada dođe do pogreške
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex, _logger);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception, ILogger logger)
        {
            HttpStatusCode code = HttpStatusCode.InternalServerError; // Pretpostavljeni status kod
            var errorResponse = new ApiResponse<object>();

            // Određivanje HTTP status koda i poruke na temelju tipa iznimke
            switch (exception)
            {
                case NotFoundException notFoundEx:
                    // 404 Not Found - resurs nije pronađen
                    code = HttpStatusCode.NotFound;
                    errorResponse = ApiResponse<object>.ErrorResponse(notFoundEx.Message, null, (int)code);
                    break;

                case Models.Exceptions.ValidationException validationEx:
                    // 400 Bad Request - nevažeći podaci
                    code = HttpStatusCode.BadRequest;
                    errorResponse = ApiResponse<object>.ErrorResponse(validationEx.Message, null, (int)code);
                    break;

                case ForbiddenAccessException forbiddenEx:
                    // 403 Forbidden - pristup zabranjen
                    code = HttpStatusCode.Forbidden;
                    errorResponse = ApiResponse<object>.ErrorResponse(forbiddenEx.Message, null, (int)code);
                    break;

                case Models.Exceptions.AuthenticationException authEx:
                    // 401 Unauthorized - pogreška autentifikacije
                    code = HttpStatusCode.Unauthorized;
                    errorResponse = ApiResponse<object>.ErrorResponse(authEx.Message, null, (int)code);
                    break;

                case ConflictException conflictEx:
                    // 409 Conflict - konflikt pri obradi zahtjeva
                    code = HttpStatusCode.Conflict;
                    errorResponse = ApiResponse<object>.ErrorResponse(conflictEx.Message, null, (int)code);
                    break;

                default:
                    // 500 Internal Server Error - neočekivana greška
                    logger.LogError(exception, "NEUHVAĆENA IZNIMKA: {ExceptionMessage}", exception.Message);
                    errorResponse = ApiResponse<object>.ErrorResponse(
                        "Došlo je do neočekivane greške. Pokušajte ponovo ili kontaktirajte administratora.",
                        null,
                        (int)code);
                    break;
            }

            // Postavljanje status koda i vraćanje JSON odgovora
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)code;

            var result = JsonSerializer.Serialize(errorResponse);
            await context.Response.WriteAsync(result);
        }
    }
}
