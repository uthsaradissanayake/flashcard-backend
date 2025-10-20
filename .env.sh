# Server Configuration
PORT=3001
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production-please

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000

# Database Configuration - Development (Local)
DB_HOST=localhost
DB_PORT=5432
DB_USER=flashcard_user
DB_PASSWORD=your_password
DB_NAME=flashcard_db

# Database Configuration - Production (Use this OR the individual settings above)
# DATABASE_URL=postgresql://username:password@hostname:port/database

# Optional: Logging Configuration
LOG_LEVEL=info

# Optional: File Upload Configuration (for future image support)
MAX_FILE_SIZE=10mb
ALLOWED_FILE_TYPES=jpg,jpeg,png,gif,webp

# Optional: Email Configuration (for future features)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your-email@gmail.com
# SMTP_PASS=your-app-password

# Optional: Redis Configuration (for session storage, caching)
# REDIS_URL=redis://localhost:6379