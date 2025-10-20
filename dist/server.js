"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const ts_fsrs_1 = require("ts-fsrs");
const compression_1 = __importDefault(require("compression"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const helmet_1 = __importDefault(require("helmet"));
const dotenv_1 = __importDefault(require("dotenv"));
const database_1 = __importDefault(require("./config/database"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = parseInt(process.env.PORT || '3001', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use((0, helmet_1.default)({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use((0, compression_1.default)());
app.set('trust proxy', 1);
const limiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: NODE_ENV === 'production' ? 100 : 1000,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    FRONTEND_URL,
];
app.use((0, cors_1.default)({
    origin: function (origin, callback) {
        if (!origin)
            return callback(null, true);
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            console.log(`CORS blocked origin: ${origin}`);
            callback(new Error(`Origin ${origin} not allowed by CORS`));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));
app.use(express_1.default.json({ limit: '10mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
if (NODE_ENV === 'development') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
        next();
    });
}
const f = (0, ts_fsrs_1.fsrs)();
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            res.status(401).json({ error: 'Access token required' });
            return;
        }
        const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch (error) {
        console.error('JWT verification failed:', error);
        res.status(403).json({ error: 'Invalid or expired token' });
        return;
    }
};
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: NODE_ENV,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
    });
});
app.get('/', (req, res) => {
    res.json({
        message: 'Flashcard API Server',
        version: '1.0.0',
        environment: NODE_ENV,
        endpoints: {
            health: '/health',
            auth: '/api/auth/*',
            decks: '/api/decks',
            cards: '/api/cards/*',
            review: '/api/review/*'
        }
    });
});
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, first_name, last_name } = req.body;
        if (!email || !password || !first_name || !last_name) {
            res.status(400).json({ error: 'All fields are required' });
            return;
        }
        if (password.length < 6) {
            res.status(400).json({ error: 'Password must be at least 6 characters' });
            return;
        }
        const existingUser = await (0, database_1.default)('users').where('email', email).first();
        if (existingUser) {
            res.status(400).json({ error: 'User already exists with this email' });
            return;
        }
        const password_hash = await bcrypt_1.default.hash(password, 12);
        const [newUser] = await (0, database_1.default)('users')
            .insert({
            email: email.toLowerCase(),
            password_hash,
            first_name,
            last_name,
        })
            .returning(['id', 'email', 'first_name', 'last_name', 'created_at']);
        const token = jsonwebtoken_1.default.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: newUser.id,
                email: newUser.email,
                first_name: newUser.first_name,
                last_name: newUser.last_name,
            },
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            res.status(400).json({ error: 'Email and password are required' });
            return;
        }
        const user = await (0, database_1.default)('users').where('email', email.toLowerCase()).first();
        if (!user) {
            res.status(400).json({ error: 'Invalid credentials' });
            return;
        }
        const validPassword = await bcrypt_1.default.compare(password, user.password_hash);
        if (!validPassword) {
            res.status(400).json({ error: 'Invalid credentials' });
            return;
        }
        const token = jsonwebtoken_1.default.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
            },
        });
    }
    catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/api/decks', authenticateToken, async (req, res) => {
    try {
        const userDecks = await (0, database_1.default)('decks')
            .where('user_id', req.user.id)
            .orderBy('created_at', 'desc');
        const decksWithStats = await Promise.all(userDecks.map(async (deck) => {
            const totalCards = await (0, database_1.default)('cards').where('deck_id', deck.id).count('id as count').first();
            const dueCards = await (0, database_1.default)('cards')
                .where('deck_id', deck.id)
                .where('due_date', '<=', new Date())
                .count('id as count')
                .first();
            return {
                ...deck,
                total_cards: parseInt(totalCards?.count) || 0,
                due_cards: parseInt(dueCards?.count) || 0,
            };
        }));
        res.json(decksWithStats);
    }
    catch (error) {
        console.error('Get decks error:', error);
        res.status(500).json({ error: 'Failed to fetch decks' });
    }
});
app.post('/api/decks', authenticateToken, async (req, res) => {
    try {
        const { name, description } = req.body;
        if (!name || name.trim().length === 0) {
            res.status(400).json({ error: 'Deck name is required' });
            return;
        }
        const existingDeck = await (0, database_1.default)('decks')
            .where('user_id', req.user.id)
            .where('name', name.trim())
            .first();
        if (existingDeck) {
            res.status(400).json({ error: 'Deck name already exists' });
            return;
        }
        const [newDeck] = await (0, database_1.default)('decks')
            .insert({
            user_id: req.user.id,
            name: name.trim(),
            description: description?.trim() || '',
        })
            .returning('*');
        res.status(201).json({
            ...newDeck,
            total_cards: 0,
            due_cards: 0,
        });
    }
    catch (error) {
        console.error('Create deck error:', error);
        res.status(500).json({ error: 'Failed to create deck' });
    }
});
app.put('/api/decks/:id', authenticateToken, async (req, res) => {
    try {
        const deckId = parseInt(req.params.id);
        const { name, description } = req.body;
        if (!deckId || isNaN(deckId)) {
            res.status(400).json({ error: 'Invalid deck ID' });
            return;
        }
        const deck = await (0, database_1.default)('decks')
            .where('id', deckId)
            .where('user_id', req.user.id)
            .first();
        if (!deck) {
            res.status(404).json({ error: 'Deck not found' });
            return;
        }
        const [updatedDeck] = await (0, database_1.default)('decks')
            .where('id', deckId)
            .update({
            name: name?.trim() || deck.name,
            description: description?.trim() || deck.description,
            updated_at: new Date(),
        })
            .returning('*');
        res.json(updatedDeck);
    }
    catch (error) {
        console.error('Update deck error:', error);
        res.status(500).json({ error: 'Failed to update deck' });
    }
});
app.delete('/api/decks/:id', authenticateToken, async (req, res) => {
    try {
        const deckId = parseInt(req.params.id);
        if (!deckId || isNaN(deckId)) {
            res.status(400).json({ error: 'Invalid deck ID' });
            return;
        }
        const deck = await (0, database_1.default)('decks')
            .where('id', deckId)
            .where('user_id', req.user.id)
            .first();
        if (!deck) {
            res.status(404).json({ error: 'Deck not found' });
            return;
        }
        await (0, database_1.default)('cards').where('deck_id', deckId).del();
        await (0, database_1.default)('decks').where('id', deckId).del();
        res.json({ message: 'Deck deleted successfully' });
    }
    catch (error) {
        console.error('Delete deck error:', error);
        res.status(500).json({ error: 'Failed to delete deck' });
    }
});
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    });
});
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method,
    });
});
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});
process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    process.exit(0);
});
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${NODE_ENV}`);
    console.log(`📱 Frontend URL: ${FRONTEND_URL}`);
    console.log(`❤️  Health check: http://localhost:${PORT}/health`);
    if (NODE_ENV === 'development') {
        console.log(`🔗 Local API: http://localhost:${PORT}/api`);
    }
});
exports.default = app;
