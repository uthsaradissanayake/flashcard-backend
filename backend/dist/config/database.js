"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.testConnection = void 0;
const knex_1 = __importDefault(require("knex"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL;
const config = {
    client: 'postgresql',
    connection: NODE_ENV === 'development'
        ? {
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432'),
            user: process.env.DB_USER || 'flashcard_user',
            password: process.env.DB_PASSWORD || 'your_password',
            database: process.env.DB_NAME || 'flashcard_db',
        }
        : {
            connectionString: DATABASE_URL,
            ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
        },
    pool: {
        min: NODE_ENV === 'production' ? 2 : 1,
        max: NODE_ENV === 'production' ? 10 : 5,
        createTimeoutMillis: 3000,
        acquireTimeoutMillis: 30000,
        idleTimeoutMillis: 30000,
        reapIntervalMillis: 1000,
        createRetryIntervalMillis: 100,
        propagateCreateError: false
    },
    migrations: {
        tableName: 'knex_migrations',
        directory: './migrations',
    },
    seeds: {
        directory: './seeds',
    },
    debug: NODE_ENV === 'development',
    postProcessResponse: (result, queryContext) => {
        if (Array.isArray(result)) {
            return result.map(row => processDateFields(row));
        }
        else if (result && typeof result === 'object') {
            return processDateFields(result);
        }
        return result;
    },
};
function processDateFields(row) {
    if (!row || typeof row !== 'object')
        return row;
    const dateFields = ['created_at', 'updated_at', 'due_date', 'last_review'];
    const processedRow = { ...row };
    dateFields.forEach(field => {
        if (processedRow[field] && typeof processedRow[field] === 'string') {
            processedRow[field] = new Date(processedRow[field]);
        }
    });
    return processedRow;
}
const db = (0, knex_1.default)(config);
const testConnection = async () => {
    try {
        await db.raw('SELECT 1+1 AS result');
        console.log('✅ Database connection successful');
        return true;
    }
    catch (error) {
        console.error('❌ Database connection failed:', error);
        return false;
    }
};
exports.testConnection = testConnection;
if (NODE_ENV !== 'test') {
    testConnection();
}
process.on('SIGINT', async () => {
    console.log('Closing database connection...');
    await db.destroy();
    process.exit(0);
});
process.on('SIGTERM', async () => {
    console.log('Closing database connection...');
    await db.destroy();
    process.exit(0);
});
exports.default = db;
