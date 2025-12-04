import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import OpenAI from 'openai';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// SQLite Database Setup
const dbPath = join(__dirname, 'database.db');
const db = new Database(dbPath);
console.log('Connected to SQLite database');

// Initialize database
function initializeDatabase() {
  // Videos table
  db.exec(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    topic TEXT,
    difficulty TEXT,
    filepath TEXT NOT NULL,
    course_id INTEGER,
    transcript TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Courses table
  db.exec(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Users table (updated with authentication)
  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT,
    role TEXT DEFAULT 'learner',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Backwards-compatible migrations for existing databases
  try {
    db.exec('ALTER TABLE users ADD COLUMN email TEXT');
  } catch (e) {
    // Column might already exist
  }

  try {
    db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
  } catch (e) {
    // Column might already exist
  }

  try {
    db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'learner'");
  } catch (e) {
    // Column might already exist
  }

  // Add user_id to videos if it doesn't exist
  try {
    db.exec('ALTER TABLE videos ADD COLUMN user_id INTEGER');
  } catch (e) {
    // Column might already exist
  }

  // Add transcript to videos if it doesn't exist
  try {
    db.exec('ALTER TABLE videos ADD COLUMN transcript TEXT');
  } catch (e) {
    // Column might already exist
  }
  
  // Add user_id to courses if it doesn't exist
  try {
    db.exec('ALTER TABLE courses ADD COLUMN user_id INTEGER');
  } catch (e) {
    // Column might already exist
  }

  // Playlists table
  db.exec(`CREATE TABLE IF NOT EXISTS playlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    topic TEXT,
    video_ids TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Add title and topic to playlists if they don't exist
  try {
    db.exec('ALTER TABLE playlists ADD COLUMN title TEXT');
  } catch (e) {
    // Column might already exist
  }

  try {
    db.exec('ALTER TABLE playlists ADD COLUMN topic TEXT');
  } catch (e) {
    // Column might already exist
  }

  // Insert sample data if database is empty
  const count = db.prepare('SELECT COUNT(*) as count FROM videos').get();
  if (count.count === 0) {
    insertSampleData();
  }
}

function insertSampleData() {
  // Insert sample course
  const stmt = db.prepare('INSERT INTO courses (title, description) VALUES (?, ?)');
  const result = stmt.run('Introduction to React', 'Learn React basics in bite-sized videos');
  console.log('Sample course created with ID:', result.lastInsertRowid);
}

initializeDatabase();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Multer configuration for video uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'video-' + uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only video files are allowed'));
    }
  }
});

// API Routes

// Health/root route
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'MoshiMoshi backend is running. Use /api/... endpoints or open the React app on http://localhost:5173.',
  });
});

// Authentication Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, name, password } = req.body;

  if (!email || !name || !password) {
    return res.status(400).json({ error: 'Email, name, and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    // Check if user already exists
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert user
    const stmt = db.prepare('INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)');
    const result = stmt.run(email, name, passwordHash, 'learner');

    // Generate JWT token
    const token = jwt.sign(
      { id: result.lastInsertRowid, email, name, role: 'learner' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: result.lastInsertRowid,
        email,
        name,
        role: 'learner'
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT id, email, name, role FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Upload video (protected - requires authentication)
app.post('/api/upload', authenticateToken, upload.single('video'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No video file uploaded' });
  }

  const { title, topic, difficulty, courseId, transcript } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }

  const filepath = `/uploads/${req.file.filename}`;
  
  try {
    // Determine transcript: use provided one, or auto-generate via OpenAI Whisper if available
    let finalTranscript = transcript || null;

    // Try auto-transcription if no manual transcript provided and OpenAI is configured
    if (!finalTranscript && openai) {
      try {
        const fullPath = join(uploadsDir, req.file.filename);
        
        // Check if file exists before trying to transcribe
        if (!fs.existsSync(fullPath)) {
          console.warn('Video file not found for transcription:', fullPath);
        } else {
          const audioStream = fs.createReadStream(fullPath);

          // Set a timeout for transcription (30 seconds)
          const transcriptionPromise = openai.audio.transcriptions.create({
            file: audioStream,
            model: 'whisper-1',
            response_format: 'text',
          });

          const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Transcription timeout')), 30000)
          );

          const transcription = await Promise.race([transcriptionPromise, timeoutPromise]);

          if (transcription && typeof transcription === 'string') {
            finalTranscript = transcription;
            console.log('Auto-transcription successful, length:', finalTranscript.length);
          } else if (transcription && transcription.text) {
            finalTranscript = transcription.text;
            console.log('Auto-transcription successful, length:', finalTranscript.length);
          }
        }
      } catch (transcribeErr) {
        console.error('Auto-transcription failed (continuing without transcript):', transcribeErr.message || transcribeErr);
        // Continue without transcript if transcription fails - video upload should still succeed
        finalTranscript = null;
      }
    }

    // Save video to database (with or without transcript)
    const stmt = db.prepare(
      `INSERT INTO videos (title, topic, difficulty, filepath, course_id, user_id, transcript) VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const result = stmt.run(title, topic || null, difficulty || null, filepath, courseId || null, req.user.id, finalTranscript);
    
    console.log('Video uploaded successfully, ID:', result.lastInsertRowid, 'Has transcript:', !!finalTranscript);
    
    res.json({
      id: result.lastInsertRowid,
      title,
      topic,
      difficulty,
      filepath,
      courseId: courseId || null,
      hasTranscript: !!finalTranscript
    });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Failed to save video metadata: ' + (err.message || 'Unknown error') });
  }
});

// Get feed (all videos)
app.get('/api/feed', (req, res) => {
  const { search, topic } = req.query;

  try {
    let query = `
      SELECT v.*, c.title as course_title, u.name as user_name
      FROM videos v 
      LEFT JOIN courses c ON v.course_id = c.id 
      LEFT JOIN users u ON v.user_id = u.id
    `;

    const conditions = [];
    const params = [];

    if (topic) {
      conditions.push('LOWER(v.topic) = LOWER(?)');
      params.push(topic);
    }

    if (search) {
      conditions.push('(LOWER(v.title) LIKE LOWER(?) OR LOWER(v.topic) LIKE LOWER(?))');
      params.push(`%${search}%`, `%${search}%`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY v.created_at DESC';

    const rows = db.prepare(query).all(...params);
    res.json(rows);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Debug endpoint to inspect transcript and AI conditions
app.get('/api/video/:id/debug', (req, res) => {
  const videoId = req.params.id;

  try {
    const row = db.prepare('SELECT id, title, topic, transcript FROM videos WHERE id = ?').get(videoId);

    if (!row) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const hasTranscript = !!(row.transcript && row.transcript.trim().length > 0);
    const transcriptLength = row.transcript ? row.transcript.length : 0;
    const canUseAI = !!(openai && transcriptLength > 20);

    res.json({
      id: row.id,
      title: row.title,
      topic: row.topic,
      hasTranscript,
      transcriptLength,
      transcriptPreview: row.transcript ? row.transcript.slice(0, 200) : null,
      openAIConfigured: !!openai,
      willUseAIForSummaryAndQuiz: canUseAI,
    });
  } catch (err) {
    console.error('Debug video error:', err);
    return res.status(500).json({ error: 'Failed to fetch debug info' });
  }
});

// Get single video
app.get('/api/video/:id', (req, res) => {
  const videoId = req.params.id;
  
  try {
    const row = db.prepare(
      `SELECT v.*, c.title as course_title, c.description as course_description
       FROM videos v 
       LEFT JOIN courses c ON v.course_id = c.id 
       WHERE v.id = ?`
    ).get(videoId);
    
    if (!row) {
      return res.status(404).json({ error: 'Video not found' });
    }
    res.json(row);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch video' });
  }
});

// Helper: curated fallback summaries for common topics
function buildCuratedSummary(row, aiErr) {
  const topic = (row.topic || '').toLowerCase();
  const exceededQuota =
    aiErr &&
    (aiErr.code === 'insufficient_quota' ||
      aiErr.status === 429 ||
      aiErr.type === 'insufficient_quota' ||
      (aiErr.error && aiErr.error.code === 'insufficient_quota'));
  const hasTranscript = row.transcript && row.transcript.trim().length > 20;

  let summary;

  if (topic.includes('react')) {
    summary = {
      points: [
        'React breaks the UI into small, reusable components that each handle their own markup and behavior.',
        'Props let parent components configure children, while state lets a component remember information between renders.',
        'React encourages one-way data flow: parents pass data down, and children raise events back up instead of mutating shared state directly.',
        'Modern React code often uses hooks (like useState and useEffect) instead of class lifecycle methods to manage state and side effects.'
      ],
      keyConcepts: ['Components', 'Props', 'State', 'Hooks', 'One-way data flow']
    };
  } else if (topic.includes('next')) {
    summary = {
      points: [
        'Next.js builds on React and uses file-based routing: every file in the pages/app directory becomes a route.',
        'You can render pages on the server (SSR) or at build time (SSG) to improve performance and SEO.',
        'API routes live next to your React code so a single project can serve both frontend pages and backend endpoints.',
        'Next.js handles bundling, code-splitting, and asset optimization for you, so you can focus on building features.'
      ],
      keyConcepts: ['File-based routing', 'SSR', 'SSG', 'API routes', 'Performance']
    };
  } else if (topic.includes('fullstack')) {
    summary = {
      points: [
        'A fullstack app connects a client-side UI (often React) to a backend API that exposes business logic.',
        'The backend talks to a database to store and query persistent data such as users, posts, or orders.',
        'Authentication and authorization flow across the stack, so the frontend only shows data the current user is allowed to see.',
        'Clear API contracts (request and response shapes) help the frontend and backend teams move independently.'
      ],
      keyConcepts: ['Frontend', 'Backend', 'Database', 'HTTP API', 'Auth']
    };
  } else if (
    topic.includes('agentic') ||
    topic.includes('ai agents') ||
    (topic.includes('agent') && topic.includes('ai')) ||
    topic.includes('open ai') ||
    topic === 'ai'
  ) {
    summary = {
      points: [
        'An AI agent is more than a single model call: it plans a sequence of steps to move from a user goal to a result.',
        'Agents use tools (like APIs, databases, or code execution) to gather information and take actions the model alone cannot.',
        'Short-term memory helps an agent keep track of the current task, while long-term memory can store facts or preferences across sessions.',
        'Common use cases include research assistants, coding copilots, support bots, and workflow automation that runs in the background.'
      ],
      keyConcepts: ['AI agents', 'Tools', 'Memory', 'Planning', 'Automation']
    };
  } else {
    summary = {
      points: [
        `You walk through the fundamental ideas behind ${row.topic || 'this topic'} in a short, focused session.`,
        'Concepts are introduced one at a time so you see what each idea means before combining them together.',
        'Concrete examples connect the theory to something practical you might build or use.',
        'By the end you should be able to explain the core idea in your own words and recognize it in real projects.'
      ],
      keyConcepts: [row.topic || 'Core concept', 'Examples', 'Real-world usage', 'Fundamentals']
    };
  }

  if (exceededQuota) {
    summary.note =
      'AI-powered summary is temporarily unavailable because your OpenAI plan quota was exceeded. Showing a preset summary instead.';
  } else if (!hasTranscript) {
    if (openai) {
      summary.note =
        'No transcript was provided for this video. Summary is generated from the topic and title instead of a full transcript.';
    } else {
      summary.note =
        'No transcript was provided and AI is disabled for this backend. Showing a preset summary for this topic.';
    }
  }

  return summary;
}

// Helper: curated fallback quizzes for common topics
function buildCuratedQuiz(row, aiErr) {
  const topic = (row.topic || '').toLowerCase();
  const exceededQuota =
    aiErr &&
    (aiErr.code === 'insufficient_quota' ||
      aiErr.status === 429 ||
      aiErr.type === 'insufficient_quota' ||
      (aiErr.error && aiErr.error.code === 'insufficient_quota'));
  const hasTranscript = row.transcript && row.transcript.trim().length > 20;

  let quiz;

  if (topic.includes('react')) {
    quiz = {
      questions: [
        {
          id: 1,
          question: 'What is the main purpose of a React component?',
          options: [
            'To encapsulate UI and behavior into a reusable piece',
            'To directly manipulate the DOM manually',
            'To store global CSS styles',
            'To manage the database connection'
          ],
          correctAnswer: 0
        },
        {
          id: 2,
          question: 'How does data typically flow between React components?',
          options: [
            'From parent to child via props',
            'From child to parent via CSS',
            'Randomly between components',
            'Directly from the database into every component'
          ],
          correctAnswer: 0
        },
        {
          id: 3,
          question: 'What is React state used for?',
          options: [
            'To remember values between renders',
            'To define project folder structure',
            'To configure the build pipeline',
            'To write SQL queries'
          ],
          correctAnswer: 0
        }
      ]
    };
  } else if (topic.includes('next')) {
    quiz = {
      questions: [
        {
          id: 1,
          question: 'How do you create a new page in a basic Next.js app?',
          options: [
            'Add a file inside the pages (or app) directory',
            'Edit the package.json file',
            'Create a new HTML file in the public folder',
            'Write SQL migrations'
          ],
          correctAnswer: 0
        },
        {
          id: 2,
          question: 'Which feature is a key advantage of Next.js over plain React?',
          options: [
            'Built-in server-side rendering',
            'Support for CSS',
            'Ability to run JavaScript',
            'Using HTML without JSX'
          ],
          correctAnswer: 0
        },
        {
          id: 3,
          question: 'What is an API route in Next.js?',
          options: [
            'A backend endpoint defined in the project',
            'A special kind of React hook',
            'A configuration file for routing',
            'A database table'
          ],
          correctAnswer: 0
        }
      ]
    };
  } else if (topic.includes('fullstack')) {
    quiz = {
      questions: [
        {
          id: 1,
          question: 'Which combination best describes a full-stack application?',
          options: [
            'Frontend, backend, and database working together',
            'Only a React frontend',
            'Only a Node.js backend',
            'Just a static HTML file'
          ],
          correctAnswer: 0
        },
        {
          id: 2,
          question: 'How does the frontend usually talk to the backend?',
          options: [
            'Via HTTP requests (REST/JSON)',
            'By sharing a database',
            'Using CSS files',
            'Through the .env file'
          ],
          correctAnswer: 0
        },
        {
          id: 3,
          question: 'What is the role of authentication in a full-stack app?',
          options: [
            'To identify and authorize users across the stack',
            'To style the UI',
            'To compress images',
            'To deploy the app'
          ],
          correctAnswer: 0
        }
      ]
    };
  } else if (
    topic.includes('agentic') ||
    topic.includes('ai agents') ||
    (topic.includes('agent') && topic.includes('ai')) ||
    topic.includes('open ai') ||
    topic === 'ai'
  ) {
    quiz = {
      questions: [
        {
          id: 1,
          question: 'What makes an AI system “agentic”?',
          options: [
            'It can take a sequence of tool-using actions toward a goal',
            'It only answers a single prompt',
            'It can only generate images',
            'It always runs in the browser'
          ],
          correctAnswer: 0
        },
        {
          id: 2,
          question: 'What are tools in the context of AI agents?',
          options: [
            'External capabilities the agent can call, like APIs or code',
            'Color palettes for UI design',
            'Database tables',
            'React components'
          ],
          correctAnswer: 0
        },
        {
          id: 3,
          question: 'Why is memory useful for AI agents?',
          options: [
            'So they can remember past steps and user preferences',
            'So they can store CSS styles',
            'So they can deploy apps',
            'So they can manage databases directly'
          ],
          correctAnswer: 0
        }
      ]
    };
  } else {
    quiz = {
      questions: [
        {
          id: 1,
          question: 'What is one benefit of learning a topic in short, focused sessions?',
          options: [
            'It is easier to stay focused and remember each idea',
            'It always covers every possible detail at once',
            'It removes the need to practise',
            'It only works for visual topics'
          ],
          correctAnswer: 0
        },
        {
          id: 2,
          question: 'When you study a new concept, which approach helps most?',
          options: [
            'See a clear explanation, then a concrete example',
            'Jump straight into a long project with no explanation',
            'Only memorise definitions',
            'Ignore mistakes and never review'
          ],
          correctAnswer: 0
        },
        {
          id: 3,
          question: 'Why is it useful to revisit a topic after watching a short lesson?',
          options: [
            'Spaced repetition helps move ideas into long‑term memory',
            'It makes the content longer but not clearer',
            'It only changes the video resolution',
            'It replaces practice with theory'
          ],
          correctAnswer: 0
        }
      ]
    };
  }

  if (exceededQuota) {
    quiz.note =
      'AI-powered quiz generation is temporarily unavailable because your OpenAI plan quota was exceeded. Showing a preset quiz instead.';
  } else if (!hasTranscript) {
    if (openai) {
      quiz.note =
        'No transcript was provided for this video. Quiz is generated from the topic and title instead of a full transcript.';
    } else {
      quiz.note =
        'No transcript was provided and AI is disabled for this backend. Showing a preset quiz for this topic.';
    }
  }

  return quiz;
}

// Get video summary (AI-powered when possible)
app.get('/api/video/:id/summary', async (req, res) => {
  // Disable caching so you always see fresh content
  res.set('Cache-Control', 'no-store');

  const videoId = req.params.id;
  
  try {
    const row = db.prepare('SELECT title, topic, transcript FROM videos WHERE id = ?').get(videoId);
    
    if (!row) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const hasTranscript = row.transcript && row.transcript.trim().length > 20;

    // If we have OpenAI, try to generate summary (with transcript if available, or with topic+title if not)
    if (openai) {
      try {
        let prompt;
        if (hasTranscript) {
          // Use transcript if available
          prompt = `Transcript:\n\n${row.transcript}\n\nUsing ONLY the wording and ideas from this transcript (do not invent generic learning advice), return JSON:\n{\n  "points": [\"point1\", \"point2\", ...],\n  "keyConcepts": [\"concept1\", \"concept2\", ...]\n}\n\n- "points": 3–5 detailed takeaways that reference specific terms, steps, or examples from the transcript.\n- "keyConcepts": 3–7 short phrases or terms that actually appear in or obviously derive from the transcript.`;
        } else {
          // Use topic and title if no transcript
          prompt = `Video Title: ${row.title}\nTopic: ${row.topic || 'General'}\n\nBased on this title and topic, create an educational summary for a short bite-sized learning video. Return JSON:\n{\n  "points": [\"point1\", \"point2\", ...],\n  "keyConcepts": [\"concept1\", \"concept2\", ...]\n}\n\n- "points": 3–5 detailed educational takeaways that explain what someone would learn from this video.\n- "keyConcepts": 3–7 key terms or concepts related to this topic.`;
        }

        const completion = await openai.chat.completions.create({
          model: 'gpt-4o-mini',
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'system',
              content: hasTranscript
                ? 'You summarize short educational video transcripts into concrete, transcript-grounded notes. Always base output ONLY on the transcript text provided.'
                : 'You create educational summaries for bite-sized learning videos based on their title and topic. Make the summary informative and educational.',
            },
            {
              role: 'user',
              content: prompt,
            },
          ],
        });

        const content = completion.choices[0]?.message?.content || '{}';
        const parsed = JSON.parse(content);

        const summary = {
          points: parsed.points || [],
          keyConcepts: parsed.keyConcepts || [],
        };

        return res.json(summary);
      } catch (aiErr) {
        console.error('OpenAI summary error:', aiErr);
        // Fallback to curated summary below
        const summary = buildCuratedSummary(row, aiErr);
        return res.json(summary);
      }
    }

    // Fallback summary (if no OpenAI key configured)
    const summary = buildCuratedSummary(row, null);
    return res.json(summary);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// Get video quiz (AI-powered when possible)
app.get('/api/video/:id/quiz', async (req, res) => {
  // Disable caching so you always see fresh content
  res.set('Cache-Control', 'no-store');

  const videoId = req.params.id;
  
  try {
    const row = db.prepare('SELECT title, topic, transcript FROM videos WHERE id = ?').get(videoId);
    
    if (!row) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const hasTranscript = row.transcript && row.transcript.trim().length > 20;

    // If we have OpenAI, try to generate quiz (with transcript if available, or with topic+title if not)
    if (openai) {
      try {
        let prompt;
        if (hasTranscript) {
          // Use transcript if available
          prompt = `Transcript:\n\n${row.transcript}\n\nUsing ONLY this transcript, create EXACTLY 3 multiple-choice questions that test understanding of the real content (facts, steps, definitions, examples).\n\nRules:\n- Each question must reference specific details or terms from the transcript (not generic study tips).\n- Each question must have 4 options.\n- Exactly one option is correct.\n\nReturn JSON only in this format:\n{\n  "questions": [\n    {\n      "question": "string",\n      "options": ["option1", "option2", "option3", "option4"],\n      "correctAnswer": 0\n    },\n    ...\n  ]\n}`;
        } else {
          // Use topic and title if no transcript
          prompt = `Video Title: ${row.title}\nTopic: ${row.topic || 'General'}\n\nBased on this title and topic, create EXACTLY 3 educational multiple-choice questions that test understanding of this topic.\n\nRules:\n- Each question should test key concepts related to this topic.\n- Each question must have 4 options.\n- Exactly one option is correct.\n- Make questions educational and relevant to the topic.\n\nReturn JSON only in this format:\n{\n  "questions": [\n    {\n      "question": "string",\n      "options": ["option1", "option2", "option3", "option4"],\n      "correctAnswer": 0\n    },\n    ...\n  ]\n}`;
        }

        const completion = await openai.chat.completions.create({
          model: 'gpt-4o-mini',
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'system',
              content: hasTranscript
                ? 'You create concrete multiple-choice questions strictly grounded in the provided transcript. Do not ask generic learning questions; every question must be answerable from the transcript text.'
                : 'You create educational multiple-choice questions for bite-sized learning videos based on their title and topic. Make questions that test understanding of key concepts.',
            },
            {
              role: 'user',
              content: prompt,
            },
          ],
        });

        const content = completion.choices[0]?.message?.content || '{}';
        const parsed = JSON.parse(content);

        const quiz = {
          questions:
            parsed.questions?.map((q, index) => ({
              id: index + 1,
              question: q.question,
              options: q.options,
              correctAnswer: q.correctAnswer,
            })) || [],
        };

        return res.json(quiz);
      } catch (aiErr) {
        console.error('OpenAI quiz error:', aiErr);
        // Fallback to curated quiz below
        const quiz = buildCuratedQuiz(row, aiErr);
        return res.json(quiz);
      }
    }

    // Fallback quiz (if no OpenAI key configured)
    const quiz = buildCuratedQuiz(row, null);
    return res.json(quiz);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch quiz' });
  }
});

// Create course (protected - requires authentication)
app.post('/api/course', authenticateToken, (req, res) => {
  const { title, description } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }
  
  try {
    const stmt = db.prepare('INSERT INTO courses (title, description, user_id) VALUES (?, ?, ?)');
    const result = stmt.run(title, description || null, req.user.id);
    
    res.json({
      id: result.lastInsertRowid,
      title,
      description
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to create course' });
  }
});

// Get all courses
app.get('/api/courses', (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    res.json(rows);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch courses' });
  }
});

// Get course with videos
app.get('/api/course/:id', (req, res) => {
  const courseId = req.params.id;
  
  try {
    const course = db.prepare('SELECT * FROM courses WHERE id = ?').get(courseId);
    
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }
    
    const videos = db.prepare('SELECT * FROM videos WHERE course_id = ? ORDER BY created_at ASC').all(courseId);
    
    res.json({
      ...course,
      videos
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch course' });
  }
});

// Create playlist (protected - requires authentication)
app.post('/api/playlist', authenticateToken, (req, res) => {
  const { title, videoIds } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }
  
  try {
    const stmt = db.prepare('INSERT INTO playlists (user_id, title, video_ids) VALUES (?, ?, ?)');
    const result = stmt.run(req.user.id, title, JSON.stringify(videoIds || []));
    
    res.json({
      id: result.lastInsertRowid,
      userId: req.user.id,
      title,
      videoIds: videoIds || []
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to create playlist' });
  }
});

// Get or create default "Saved Videos" playlist (protected - requires authentication)
app.get('/api/playlist/default', authenticateToken, async (req, res) => {
  try {
    // Check if default playlist exists
    let playlist = db.prepare('SELECT * FROM playlists WHERE user_id = ? AND title = ?').get(req.user.id, 'Saved Videos');
    
    if (!playlist) {
      // Create default playlist
      const stmt = db.prepare('INSERT INTO playlists (user_id, title, video_ids) VALUES (?, ?, ?)');
      const result = stmt.run(req.user.id, 'Saved Videos', JSON.stringify([]));
      playlist = db.prepare('SELECT * FROM playlists WHERE id = ?').get(result.lastInsertRowid);
    }
    
    res.json({
      id: playlist.id,
      title: playlist.title,
      userId: playlist.user_id
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to get default playlist' });
  }
});

// Get user's playlists (protected - requires authentication)
app.get('/api/playlists', authenticateToken, (req, res) => {
  try {
    console.log('GET /api/playlists called for user:', req.user.id);
    const rows = db.prepare('SELECT id, title, video_ids, created_at FROM playlists WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
    
    // Parse video_ids and count videos
    const playlists = rows.map(playlist => ({
      id: playlist.id,
      title: playlist.title,
      video_ids: playlist.video_ids,
      created_at: playlist.created_at,
      videoCount: playlist.video_ids ? JSON.parse(playlist.video_ids).length : 0
    }));
    
    console.log('Returning playlists:', playlists.length);
    res.json(playlists);
  } catch (err) {
    console.error('Database error in /api/playlists:', err);
    return res.status(500).json({ error: 'Failed to fetch playlists' });
  }
});

// Get playlist with videos (protected - requires authentication)
app.get('/api/playlist/:id', authenticateToken, (req, res) => {
  const playlistId = req.params.id;
  
  try {
    const playlist = db.prepare('SELECT * FROM playlists WHERE id = ? AND user_id = ?').get(playlistId, req.user.id);
    
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }
    
    const videoIds = playlist.video_ids ? JSON.parse(playlist.video_ids) : [];
    const videos = videoIds.length > 0
      ? db.prepare(`SELECT * FROM videos WHERE id IN (${videoIds.map(() => '?').join(',')}) ORDER BY created_at ASC`).all(...videoIds)
      : [];
    
    res.json({
      id: playlist.id,
      title: playlist.title,
      userId: playlist.user_id,
      videos,
      created_at: playlist.created_at
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to fetch playlist' });
  }
});

// Add video to playlist (protected - requires authentication)
app.post('/api/playlist/:id/video', authenticateToken, (req, res) => {
  const playlistId = req.params.id;
  const { videoId } = req.body;
  
  if (!videoId) {
    return res.status(400).json({ error: 'Video ID is required' });
  }
  
  try {
    const playlist = db.prepare('SELECT * FROM playlists WHERE id = ? AND user_id = ?').get(playlistId, req.user.id);
    
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }
    
    const videoIds = playlist.video_ids ? JSON.parse(playlist.video_ids) : [];
    if (!videoIds.includes(videoId)) {
      videoIds.push(videoId);
      const stmt = db.prepare('UPDATE playlists SET video_ids = ? WHERE id = ?');
      stmt.run(JSON.stringify(videoIds), playlistId);
    }
    
    res.json({ success: true, videoIds });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to add video to playlist' });
  }
});

// Remove video from playlist (protected - requires authentication)
app.delete('/api/playlist/:id/video/:videoId', authenticateToken, (req, res) => {
  const playlistId = req.params.id;
  const videoId = parseInt(req.params.videoId);
  
  try {
    const playlist = db.prepare('SELECT * FROM playlists WHERE id = ? AND user_id = ?').get(playlistId, req.user.id);
    
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist not found' });
    }
    
    const videoIds = playlist.video_ids ? JSON.parse(playlist.video_ids) : [];
    const updatedIds = videoIds.filter(id => id !== videoId);
    
    const stmt = db.prepare('UPDATE playlists SET video_ids = ? WHERE id = ?');
    stmt.run(JSON.stringify(updatedIds), playlistId);
    
    res.json({ success: true, videoIds: updatedIds });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Failed to remove video from playlist' });
  }
});

// Debug: List all registered routes
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Registered playlist routes:');
  console.log('  GET /api/playlists');
  console.log('  GET /api/playlist/:id');
  console.log('  POST /api/playlist');
  console.log('  POST /api/playlist/:id/video');
  console.log('  DELETE /api/playlist/:id/video/:videoId');
});

