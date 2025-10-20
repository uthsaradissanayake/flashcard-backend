import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { fsrs, Card as FSRSCard, Rating, State } from 'ts-fsrs';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import db from './config/database';

// Load environment variables
dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || '3001', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Compression middleware
app.use(compression());

// Trust proxy for Render
app.set('trust proxy', 1);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'production' ? 100 : 1000, // More lenient in development
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to API routes
app.use('/api/', limiter);

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000', // Development frontend
  'http://localhost:3001', // Development backend (for testing)
  FRONTEND_URL, // Production frontend
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, curl)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`CORS blocked origin: ${origin}`);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware (development)
if (NODE_ENV === 'development') {
  app.use((req: Request, res: Response, next: NextFunction) => {
    console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
    next();
  });
}

// Types
interface User {
  id: number;
  email: string;
  password_hash: string;
  first_name: string;
  last_name: string;
  created_at: Date;
  updated_at: Date;
}

interface Deck {
  id: number;
  user_id: number;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
}

interface Card {
  id: number;
  deck_id: number;
  front_text: string;
  back_text: string;
  front_image_url?: string;
  back_image_url?: string;
  // FSRS fields
  due_date: Date;
  stability: number;
  difficulty: number;
  elapsed_days: number;
  scheduled_days: number;
  reps: number;
  lapses: number;
  state: State;
  last_review?: Date;
  created_at: Date;
  updated_at: Date;
}

// Initialize FSRS algorithm
const f = fsrs();

// JWT Authentication middleware
interface AuthRequest extends Request {
  user?: { id: number; email: string };
}

const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction): Promise<any> => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      res.status(401).json({ error: 'Access token required' });
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET) as { id: number; email: string };
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification failed:', error);
    res.status(403).json({ error: 'Invalid or expired token' });
    return;
  }
};

// Health check endpoint (required for Render)
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
  });
});

// Root endpoint
app.get('/', (req: Request, res: Response) => {
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

// Authentication Routes

// Register endpoint
app.post('/api/auth/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, first_name, last_name } = req.body;

    // Input validation
    if (!email || !password || !first_name || !last_name) {
      res.status(400).json({ error: 'All fields are required' });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters' });
      return;
    }

    // Check if user already exists
    const existingUser = await db('users').where('email', email).first();
    if (existingUser) {
      res.status(400).json({ error: 'User already exists with this email' });
      return;
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 12);

    // Create new user
    const [newUser] = await db('users')
      .insert({
        email: email.toLowerCase(),
        password_hash,
        first_name,
        last_name,
      })
      .returning(['id', 'email', 'first_name', 'last_name', 'created_at']);

    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

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
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    // Find user
    const user = await db('users').where('email', email.toLowerCase()).first();
    if (!user) {
      res.status(400).json({ error: 'Invalid credentials' });
      return;
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      res.status(400).json({ error: 'Invalid credentials' });
      return;
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Deck Management Routes

// Get all decks for authenticated user
app.get('/api/decks', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const userDecks = await db('decks')
      .where('user_id', req.user!.id)
      .orderBy('created_at', 'desc');

    // Add card statistics to each deck
    const decksWithStats = await Promise.all(
      userDecks.map(async (deck) => {
        const totalCards = await db('cards').where('deck_id', deck.id).count('id as count').first();
        const dueCards = await db('cards')
          .where('deck_id', deck.id)
          .where('due_date', '<=', new Date())
          .count('id as count')
          .first();

        return {
          ...deck,
          total_cards: parseInt(totalCards?.count as string) || 0,
          due_cards: parseInt(dueCards?.count as string) || 0,
        };
      })
    );

    res.json(decksWithStats);
  } catch (error) {
    console.error('Get decks error:', error);
    res.status(500).json({ error: 'Failed to fetch decks' });
  }
});

// Create new deck
app.post('/api/decks', authenticateToken, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { name, description } = req.body;

    if (!name || name.trim().length === 0) {
      res.status(400).json({ error: 'Deck name is required' });
      return;
    }

    // Check if deck name already exists for user
    const existingDeck = await db('decks')
      .where('user_id', req.user!.id)
      .where('name', name.trim())
      .first();

    if (existingDeck) {
      res.status(400).json({ error: 'Deck name already exists' });
      return;
    }

    const [newDeck] = await db('decks')
      .insert({
        user_id: req.user!.id,
        name: name.trim(),
        description: description?.trim() || '',
      })
      .returning('*');

    res.status(201).json({
      ...newDeck,
      total_cards: 0,
      due_cards: 0,
    });
  } catch (error) {
    console.error('Create deck error:', error);
    res.status(500).json({ error: 'Failed to create deck' });
  }
});

// Update deck
app.put('/api/decks/:id', authenticateToken, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const deckId = parseInt(req.params.id);
    const { name, description } = req.body;

    if (!deckId || isNaN(deckId)) {
      res.status(400).json({ error: 'Invalid deck ID' });
      return;
    }

    // Verify deck belongs to user
    const deck = await db('decks')
      .where('id', deckId)
      .where('user_id', req.user!.id)
      .first();

    if (!deck) {
      res.status(404).json({ error: 'Deck not found' });
      return;
    }

    const [updatedDeck] = await db('decks')
      .where('id', deckId)
      .update({
        name: name?.trim() || deck.name,
        description: description?.trim() || deck.description,
        updated_at: new Date(),
      })
      .returning('*');

    res.json(updatedDeck);
  } catch (error) {
    console.error('Update deck error:', error);
    res.status(500).json({ error: 'Failed to update deck' });
  }
});

// Delete deck and all its cards
app.delete('/api/decks/:id', authenticateToken, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const deckId = parseInt(req.params.id);

    if (!deckId || isNaN(deckId)) {
      res.status(400).json({ error: 'Invalid deck ID' });
      return;
    }

    // Verify deck belongs to user
    const deck = await db('decks')
      .where('id', deckId)
      .where('user_id', req.user!.id)
      .first();

    if (!deck) {
      res.status(404).json({ error: 'Deck not found' });
      return;
    }

    // Delete all cards in this deck first (due to foreign key constraints)
    await db('cards').where('deck_id', deckId).del();

    // Delete deck
    await db('decks').where('id', deckId).del();

    res.json({ message: 'Deck deleted successfully' });
  } catch (error) {
    console.error('Delete deck error:', error);
    res.status(500).json({ error: 'Failed to delete deck' });
  }
});

// Continue with remaining routes (cards, review, etc.)...
// [The rest of your API routes would go here - cards management, review system, etc.]

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});

// 404 handler
app.use('*', (req: Request, res: Response) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`📱 Frontend URL: ${FRONTEND_URL}`);
  console.log(`❤️  Health check: http://localhost:${PORT}/health`);
  if (NODE_ENV === 'development') {
    console.log(`🔗 Local API: http://localhost:${PORT}/api`);
  }
});

export default app;