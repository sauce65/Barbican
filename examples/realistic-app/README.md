# Realistic Barbican Example

A complete, realistic web API demonstrating all Barbican security features working together.

This example implements a simple "Task Management" API with:
- User registration and authentication
- JWT-based sessions
- Input validation
- Encrypted sensitive fields
- Audit logging
- Health checks

## Features Demonstrated

| Feature | NIST Control | Implementation |
|---------|--------------|----------------|
| Password validation | IA-5 | Registration endpoint |
| Login lockout | AC-7 | Login endpoint |
| Session management | AC-11, AC-12 | JWT middleware |
| Input validation | SI-10 | All endpoints |
| Audit logging | AU-2, AU-3 | Middleware + explicit logs |
| Rate limiting | SC-5 | Router layer |
| Security headers | CM-6 | Router layer |
| Secure errors | SI-11 | Error handling |
| Field encryption | SC-28 | Task notes field |

## Running

```bash
# Enter directory
cd examples/realistic-app

# Set required environment variables
export DATABASE_URL="postgresql://localhost/tasks"
export JWT_SECRET="your-secret-key-here"
export ENCRYPTION_KEY="32-byte-base64-encoded-key"

# Run with default (Moderate) profile
cargo run

# Or specify a profile
BARBICAN_PROFILE=fedramp-high cargo run
```

## API Endpoints

### Health
- `GET /health` - Liveness check
- `GET /health/ready` - Readiness check (includes DB)

### Authentication
- `POST /auth/register` - Create new user
- `POST /auth/login` - Authenticate and get JWT
- `POST /auth/logout` - Invalidate session

### Tasks (requires authentication)
- `GET /tasks` - List user's tasks
- `POST /tasks` - Create task
- `GET /tasks/:id` - Get task
- `PUT /tasks/:id` - Update task
- `DELETE /tasks/:id` - Delete task

## Example Requests

### Register
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "MySecurePassword123!",
    "name": "Test User"
  }'
```

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "MySecurePassword123!"
  }'
# Returns: {"token": "eyJ..."}
```

### Create Task
```bash
curl -X POST http://localhost:3000/tasks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  -d '{
    "title": "Complete security audit",
    "description": "Review all endpoints",
    "notes": "Contains sensitive details"
  }'
```

## Security Configuration

The app uses FedRAMP Moderate by default. Key settings:

| Setting | Value |
|---------|-------|
| Password min length | 15 characters |
| Max login attempts | 3 |
| Lockout duration | 30 minutes |
| Session idle timeout | 15 minutes |
| Session max lifetime | 15 minutes |
| Rate limit | 100 req/sec |

## Code Structure

```
realistic-app/
├── Cargo.toml
├── src/
│   ├── main.rs          # App setup and routing
│   ├── config.rs        # Configuration loading
│   ├── auth/
│   │   ├── mod.rs       # Auth module
│   │   ├── handlers.rs  # Login, register, logout
│   │   ├── jwt.rs       # JWT creation/validation
│   │   └── middleware.rs # Auth middleware
│   ├── tasks/
│   │   ├── mod.rs       # Tasks module
│   │   ├── handlers.rs  # CRUD handlers
│   │   └── models.rs    # Task types
│   ├── db/
│   │   ├── mod.rs       # Database module
│   │   └── queries.rs   # SQL queries
│   └── error.rs         # Error handling
└── migrations/          # Database migrations
```
