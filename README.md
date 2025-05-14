.NET Authentication

A robust authentication API built with ASP.NET Core 8, implementing modern security practices including JWT authentication, refresh token rotation, and multi-factor authentication.

## Features

- **Full Authentication Flow**
  - Registration with email verification
  - JWT-based authentication
  - Secure refresh token rotation
  - Two-factor authentication (2FA)
  - Rate limiting protection

- **Security Practices**
  - HTTP-only secure cookies for refresh tokens
  - Token theft detection
  - Email verification
  - IP and email-based rate limiting
  - Protection against common attack vectors

- **Architecture**
  - Clean separation of API, Models and Services
  - Asynchronous operations with RabbitMQ
  - Comprehensive error handling
  - Dependency injection
  - Structured logging

## Technology Stack

- ASP.NET Core 8
- Entity Framework Core
- ASP.NET Identity
- JWT Bearer Authentication
- RabbitMQ
- SQL Server
- Serilog
- Mapster

## Getting Started

### Prerequisites

- .NET 8.0 SDK
- SQL Server
- RabbitMQ (optional)
- SMTP server

### Configuration

Create a `.env` file with:

```
# Database
DB_CONNECTION_STRING=Server=localhost;Database=AuthDB;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=true

# JWT Settings
JWT_SECRET=your_very_long_secure_secret_key_here
JWT_ISSUER=AuthProject
JWT_AUDIENCE=AuthProjectClient

# SMTP Settings
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your_username
SMTP_PASSWORD=your_password
SMTP_ENABLE_SSL=true
SMTP_FROM_EMAIL=no-reply@example.com
SMTP_FROM_NAME=Auth App

# RabbitMQ Settings
RABBITMQ_HOST=localhost
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_PORT=5672
```

### Running the Application

```bash
cd Auth-BE
dotnet restore
dotnet ef database update
dotnet run --project Auth.API
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register a new user |
| `/api/auth/login` | POST | Authenticate a user |
| `/api/auth/confirm-email` | GET | Confirm user email |
| `/api/auth/resend-confirmation-email` | POST | Resend confirmation email |
| `/api/auth/two-factor` | POST | Verify 2FA code |
| `/api/auth/generate-2fa-code` | GET | Generate 2FA code |
| `/api/auth/setup-2fa` | POST | Enable 2FA for a user |
| `/api/auth/current-user` | GET | Get current user data |
| `/api/auth/logout` | POST | Logout user |

## Security Features

### Refresh Token Rotation

Each time a refresh token is used, it's invalidated and replaced with a new token, protecting against token theft and reuse attacks.

### Rate Limiting

- **auth-email**: 5 attempts per 5 minutes (login, register, 2FA)
- **ip-only**: 20 operations per 10 minutes
- **email-only**: 30 operations per 5 minutes per user

### Email Processing

Confirmation emails and 2FA codes are processed via a message queue, ensuring reliable delivery even under system load.

## Project Structure

```
Auth-BE/
├── Auth.API          # Controllers, Middleware, Configuration
├── Auth.Models       # Entities, DTOs, Exceptions
└── Auth.Services     # Business Logic, Services
```

## Future Enhancements

- OAuth provider integration
- Password recovery
- User profile management
- Role-based permissions
- API key authentication

## License

MIT
