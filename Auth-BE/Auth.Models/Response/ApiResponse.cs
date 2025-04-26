namespace Auth.Models.Response
{
    /// Generička klasa za standardizirane odgovore API-ja
    /// Osigurava konzistentnu strukturu odgovora kroz cijeli API
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public List<string> Errors { get; set; }

        public int StatusCode { get; set; }

        public ApiResponse()
        {
            Success = true;
            Message = string.Empty;
            Errors = new List<string>();
        }
        public static ApiResponse<T> SuccessResponse(T data, string message = "")
        {
            return new ApiResponse<T>
            {
                Success = true,
                Message = message,
                Data = data,
                StatusCode = 200
            };
        }

        public static ApiResponse<T> ErrorResponse(string message, List<string> errors = null, int statusCode = 400)
        {
            return new ApiResponse<T>
            {
                Success = false,
                Message = message,
                Errors = errors ?? new List<string>(),
                StatusCode = statusCode
            };
        }
    }
}
