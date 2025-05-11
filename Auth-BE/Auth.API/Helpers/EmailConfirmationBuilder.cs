namespace Auth.API.Helpers
{
    public class EmailConfirmationBuilder
    {
        public static string GetSuccessHtml()
        {
            return @"
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Email Confirmed</title>
                <style>
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        background-color: #f5f8fa;
                    }
                    .container {
                        max-width: 600px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        padding: 40px;
                        text-align: center;
                    }
                    h1 {
                        color: #2ecc71;
                        margin-bottom: 20px;
                    }
                    .icon {
                        font-size: 64px;
                        margin-bottom: 20px;
                        color: #2ecc71;
                    }
                    .message {
                        margin-bottom: 30px;
                        font-size: 18px;
                    }
                    .btn {
                        display: inline-block;
                        background-color: #3498db;
                        color: white;
                        text-decoration: none;
                        padding: 12px 24px;
                        border-radius: 4px;
                        font-weight: bold;
                        transition: background-color 0.3s;
                    }
                    .btn:hover {
                        background-color: #2980b9;
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='icon'>✓</div>
                    <h1>Email Successfully Confirmed!</h1>
                    <p class='message'>Thank you for verifying your email address. Your account is now fully activated.</p>
                    <a href='http://localhost:4200/login' class='btn'>Go to Login</a>
                </div>
            </body>
            </html>";
        }

        public static string GetErrorHtml(string errorMessage)
        {
            return $@"
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Email Confirmation Failed</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        background-color: #f5f8fa;
                    }}
                    .container {{
                        max-width: 600px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        padding: 40px;
                        text-align: center;
                    }}
                    h1 {{
                        color: #e74c3c;
                        margin-bottom: 20px;
                    }}
                    .icon {{
                        font-size: 64px;
                        margin-bottom: 20px;
                        color: #e74c3c;
                    }}
                    .message {{
                        margin-bottom: 30px;
                        font-size: 18px;
                    }}
                    .error-details {{
                        background-color: #f8f8f8;
                        padding: 15px;
                        border-radius: 4px;
                        text-align: left;
                        margin-bottom: 30px;
                    }}
                    .btn {{
                        display: inline-block;
                        background-color: #3498db;
                        color: white;
                        text-decoration: none;
                        padding: 12px 24px;
                        border-radius: 4px;
                        font-weight: bold;
                        transition: background-color 0.3s;
                    }}
                    .btn:hover {{
                        background-color: #2980b9;
                    }}
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='icon'>✗</div>
                    <h1>Email Confirmation Failed</h1>
                    <p class='message'>We encountered a problem while confirming your email address.</p>
                    <div class='error-details'>{errorMessage}</div>
                    <a href='http://localhost:4200/login' class='btn'>Return to Login</a>
                </div>
            </body>
            </html>";
        }
    }
}
