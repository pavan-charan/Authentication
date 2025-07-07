# Jatayu Authentication Microservice

A centralized authentication microservice built with FastAPI, SQLAlchemy, Alembic, and Celery, designed to provide JWT-based authentication, user management, and token handling across your microservices ecosystem.

## ✨ Features

- **Async endpoints** using FastAPI & SQLAlchemy 2.x
- **JWT access & refresh tokens** for secure authentication
- **Role-based access control** (RBAC)
- **Database migrations** with Alembic
- **Background tasks** with Celery + Redis
- **Structured logging** with optional Sentry integration
- **CORS support** for cross-origin requests
- **Comprehensive test coverage**

## 🛠️ Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.11** (or 3.10)
- **PostgreSQL** (>= 12)
- **Redis** (for Celery broker & backend)
- **Git client**

## 📁 Repository Structure

```
.
├── alembic/                       # Alembic migration environment
│   ├── env.py
│   └── versions/
├── config/
│   ├── celery_config.py
│   ├── logging_config.py
│   ├── sentry.py
│   └── settings.py                # Pydantic/dotenv settings loader
├── database/
│   ├── connection.py              # Sync & async DB sessions
│   └── models.py                  # SQLAlchemy BaseModel
├── apps/
│   └── users/
│       ├── models.py
│       ├── schemas.py
│       ├── services.py
│       ├── crud.py
│       └── routes.py
├── router.py                      # Aggregates app routers
├── main.py                        # FastAPI entrypoint
├── tests/                         # Unit & integration tests
├── .env                           # Environment variables
├── requirements.txt               
├── alembic.ini                    
└── README.md                      
```

## 🚀 Getting Started

Follow these steps to get your Jatayu service up and running locally.

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/jatayu.git
cd jatayu
```

### 2. Create & Activate Virtual Environment

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows (cmd):
venv\Scripts\activate

# On Windows (PowerShell):
venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install project dependencies
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create your environment configuration file:

```bash
cp .env.example .env
```

Edit the `.env` file in your project root with your configuration:

```env
# Project settings
PROJECT_NAME=Jatayu
PROJECT_VERSION=1.0.0
CURRENT_DEVELOPMENT_ENV=development

# Database URLs (Update with your credentials)
ASYNC_DATABASE_URL=postgresql+asyncpg://your_username:your_password@localhost:5432/jatayu_auth
SYNC_DATABASE_URL=postgresql+psycopg2://your_username:your_password@localhost:5432/jatayu_auth

# Redis for Celery
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=${REDIS_URL}
CELERY_RESULT_BACKEND=${REDIS_URL}

# Logging & Monitoring
LOG_LEVEL=INFO
SENTRY_DSN=  # Optional: Add your Sentry DSN for error tracking

# CORS origins (comma-separated or use * for development)
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Security & JWT
SECRET_KEY=your-super-secret-key-change-this-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=30
```

> **⚠️ Security Note**: Make sure to change the `SECRET_KEY` to a strong, random string in production. You can generate one using:
> ```bash
> python -c "import secrets; print(secrets.token_urlsafe(32))"
> ```

### 5. Set Up PostgreSQL Database

#### Option A: Using psql command line

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Or if you're using a different setup:
psql -U postgres -h localhost
```

```sql
-- Create database and user
CREATE DATABASE jatayu_auth;
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE jatayu_auth TO your_username;

-- Grant additional permissions for schema operations
GRANT CREATE ON DATABASE jatayu_auth TO your_username;
ALTER USER your_username CREATEDB;

-- Exit psql
\q
```

#### Option B: Using pgAdmin or other GUI tools

1. Create a new database named `jatayu_auth`
2. Create a new user with appropriate permissions
3. Update your `.env` file with the correct credentials

### 6. Run Database Migrations

Initialize and apply database migrations:

```bash
# Generate initial migration (if models exist)
python -m alembic revision --autogenerate -m "Initial migration"

# Apply migrations
python -m alembic upgrade head
```

> **Note**: If this is your first setup and no models exist yet, Alembic will create an empty migration. Subsequent migrations will automatically track your schema changes.

### 7. Start the Application

#### Start the FastAPI Application

```bash
# Development mode with auto-reload
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Or for production
uvicorn main:app --host 0.0.0.0 --port 8000
```

#### Start Celery Worker (Optional - for background tasks)

In a separate terminal:

```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Start Celery worker
celery -A config.celery_config worker --loglevel=info
```

#### Start Celery Beat (Optional - for scheduled tasks)

In another terminal:

```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Start Celery beat scheduler
celery -A config.celery_config beat --loglevel=info
```

### 8. Verify Installation

Once the application is running, you can access:

- **API Server**: http://localhost:8000
- **Health Check**: http://localhost:8000/health (if implemented)
- **API Documentation**: 
  - Swagger UI: http://localhost:8000/docs
  - ReDoc: http://localhost:8000/redoc

## 📚 API Documentation

The API documentation is automatically generated and available at:

- **Swagger UI**: `/docs` - Interactive API documentation
- **ReDoc**: `/redoc` - Alternative API documentation

Each endpoint includes:
- Request/response schemas
- Status codes
- Example requests and responses
- Authentication requirements

## 🧪 Running Tests

Run the test suite to ensure everything is working correctly:

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=apps --cov-report=html

# Run tests quietly with minimal output
pytest -q --disable-warnings --maxfail=1

# Run specific test file
pytest tests/test_users.py

# Run tests with detailed output
pytest -v
```

## 🔧 Development

### Adding New Migrations

When you modify your database models:

```bash
# Generate new migration
python -m alembic revision --autogenerate -m "Description of changes"

# Apply migration
python -m alembic upgrade head
```

### Code Quality

```bash
# Format code with black
black .

# Check code style
flake8 .

# Type checking with mypy
mypy .
```

## 🐳 Docker Support (Optional)

If you prefer using Docker:

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Import Errors in IDE (PyCharm/VS Code)

**Solution**: Ensure your IDE is using the correct Python interpreter from your virtual environment.

- **PyCharm**: Go to `Preferences → Project → Python Interpreter` and select `venv/bin/python`
- **VS Code**: Press `Ctrl+Shift+P`, type "Python: Select Interpreter", and choose the venv interpreter

#### 2. Alembic "No module named" Errors

**Solution**: Always run Alembic commands with the virtual environment's Python:

```bash
python -m alembic upgrade head
```

#### 3. Database Connection Issues

**Possible causes and solutions**:

- **PostgreSQL not running**: Start PostgreSQL service
- **Wrong credentials**: Verify database URL in `.env` file
- **Database doesn't exist**: Create the database as shown in step 5
- **Permission issues**: Ensure your user has the necessary privileges

#### 4. Dependency Installation Errors (macOS)

**Solution**: Install binary packages to avoid compilation issues:

```bash
# Install psycopg2-binary instead of psycopg2
pip install psycopg2-binary

# If you're using Python 3.13, consider using Python 3.11 or 3.10
```

#### 5. Redis Connection Issues

**Solution**: Ensure Redis is running:

```bash
# Start Redis (macOS with Homebrew)
brew services start redis

# Start Redis (Linux)
sudo systemctl start redis

# Test Redis connection
redis-cli ping
```

#### 6. Port Already in Use

**Solution**: Either stop the process using the port or use a different port:

```bash
# Find process using port 8000
lsof -i :8000

# Kill the process (replace PID with actual process ID)
kill -9 PID

# Or use a different port
uvicorn main:app --port 8001
```

## 🚀 Production Deployment

### Environment Variables

For production, ensure you set:

```env
CURRENT_DEVELOPMENT_ENV=production
SECRET_KEY=your-production-secret-key
CORS_ORIGINS=https://your-frontend-domain.com
SENTRY_DSN=your-sentry-dsn
```

### Database

- Use a managed PostgreSQL service (AWS RDS, Google Cloud SQL, etc.)
- Enable SSL connections
- Regular backups

### Security

- Use HTTPS in production
- Set strong, unique `SECRET_KEY`
- Configure proper CORS origins
- Enable rate limiting
- Use environment-specific configurations

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Search existing [GitHub Issues](https://github.com/your-org/jatayu/issues)
3. Create a new issue with detailed information
4. Reach out to the maintainers

---

**Happy coding with Jatayu!** 🎉