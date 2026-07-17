const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'ZENOX_ULTRA_HARD_SECURE_KEY';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ZenoxAdmin@2026#Secure$';
const SESSION_EXPIRY = process.env.SESSION_EXPIRY || '8h';
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const LOCK_DURATION = parseInt(process.env.LOCK_DURATION) || 15;

// ============ DATA STORE ============
const DATA_FILE = path.join(__dirname, 'data', 'users.json');

function readData() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        return { users: [], accessKeys: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ============ MIDDLEWARE ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://draw.ar-lottery01.com"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    referrerPolicy: { policy: 'same-origin' },
    frameguard: { action: 'deny' },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' }
}));

app.use(cors({
    origin: ['https://zenox-secure-v3.onrender.com', 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// XSS Protection
app.use((req, res, next) => {
    if (req.body) {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key]);
            }
        }
    }
    next();
});

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Try again later.' }
});
app.use('/api/auth/login', authLimiter);

// ============ SERVE STATIC FILES ============
app.use(express.static(path.join(__dirname, '../client')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/dashboard.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/admin.html'));
});

// ============ AUTH MIDDLEWARE ============
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided', code: 'NO_TOKEN' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }
        return res.status(401).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    }
}

function verifyAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required', code: 'ADMIN_REQUIRED' });
    }
    next();
}

// ============ API ROUTES ============

// ---------- LOGIN ----------
app.post('/api/auth/login', [
    body('deviceId').notEmpty().trim().escape(),
    body('key').notEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input', code: 'INVALID_INPUT' });
    }

    try {
        const { deviceId, key } = req.body;
        const data = readData();

        let user = data.users.find(u => u.deviceId === deviceId);

        if (user) {
            if (!user.isActive) {
                return res.status(403).json({ error: 'Account disabled', code: 'ACCOUNT_DISABLED' });
            }

            if (user.lockUntil && user.lockUntil > Date.now()) {
                const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
                return res.status(403).json({ 
                    error: `Account locked. Try again in ${remaining} minutes`,
                    code: 'ACCOUNT_LOCKED'
                });
            }

            const isValid = await bcrypt.compare(key, user.passwordHash);
            if (!isValid) {
                user.loginAttempts = (user.loginAttempts || 0) + 1;
                if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                    user.lockUntil = Date.now() + LOCK_DURATION * 60 * 1000;
                }
                writeData(data);
                return res.status(401).json({ error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
            }

            user.loginAttempts = 0;
            user.lockUntil = null;
            user.lastLogin = new Date().toISOString();
            writeData(data);

            const token = jwt.sign(
                { id: user.id, deviceId: user.deviceId, role: user.role },
                JWT_SECRET,
                { expiresIn: SESSION_EXPIRY }
            );

            return res.json({ 
                success: true, 
                token, 
                deviceId: user.deviceId, 
                role: user.role,
                expiresIn: SESSION_EXPIRY
            });
        }

        const accessKey = data.accessKeys.find(k => k.key === key && k.isActive);
        if (!accessKey) {
            return res.status(401).json({ error: 'Invalid access key', code: 'INVALID_KEY' });
        }

        if (accessKey.expiresAt && new Date(accessKey.expiresAt) < new Date()) {
            return res.status(401).json({ error: 'Key expired', code: 'KEY_EXPIRED' });
        }

        if (accessKey.maxUsage && accessKey.usageCount >= accessKey.maxUsage) {
            return res.status(401).json({ error: 'Key usage limit reached', code: 'KEY_LIMIT_REACHED' });
        }

        const passwordHash = await bcrypt.hash(key, 12);
        const newUser = {
            id: uuidv4(),
            deviceId: deviceId,
            passwordHash: passwordHash,
            role: accessKey.role || 'user',
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString(),
            loginAttempts: 0,
            lockUntil: null,
            isActive: true
        };

        data.users.push(newUser);
        accessKey.usageCount = (accessKey.usageCount || 0) + 1;
        accessKey.assignedTo = deviceId;
        writeData(data);

        const token = jwt.sign(
            { id: newUser.id, deviceId: newUser.deviceId, role: newUser.role },
            JWT_SECRET,
            { expiresIn: SESSION_EXPIRY }
        );

        return res.json({ 
            success: true, 
            token, 
            deviceId: newUser.deviceId, 
            role: newUser.role,
            expiresIn: SESSION_EXPIRY
        });

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error', code: 'SERVER_ERROR' });
    }
});

// ---------- VERIFY ----------
app.get('/api/auth/verify', verifyToken, (req, res) => {
    res.json({ 
        valid: true, 
        deviceId: req.user.deviceId, 
        role: req.user.role,
        expiresIn: SESSION_EXPIRY
    });
});

// ---------- ADMIN LOGIN ----------
app.post('/api/admin/login', [
    body('password').notEmpty().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: 'Invalid admin password' });
    }

    const token = jwt.sign(
        { id: 'admin', role: 'admin', deviceId: 'ADMIN' },
        JWT_SECRET,
        { expiresIn: SESSION_EXPIRY }
    );

    res.json({ success: true, token, role: 'admin', expiresIn: SESSION_EXPIRY });
});

// ---------- ADMIN: GET USERS ----------
app.get('/api/admin/users', verifyToken, verifyAdmin, (req, res) => {
    const data = readData();
    const users = data.users.map(u => ({
        id: u.id,
        deviceId: u.deviceId,
        role: u.role,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin,
        isActive: u.isActive,
        loginAttempts: u.loginAttempts,
        lockUntil: u.lockUntil
    }));
    res.json({ success: true, users });
});

// ---------- ADMIN: GET KEYS ----------
app.get('/api/admin/keys', verifyToken, verifyAdmin, (req, res) => {
    const data = readData();
    res.json({ success: true, keys: data.accessKeys });
});

// ---------- ADMIN: GENERATE KEY ----------
app.post('/api/admin/keys', verifyToken, verifyAdmin, [
    body('maxUsage').optional().isInt({ min: 1, max: 100 }),
    body('expiresInDays').optional().isInt({ min: 1, max: 365 }),
    body('role').optional().isIn(['user', 'admin'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { maxUsage = 1, expiresInDays = null, role = 'user' } = req.body;
    const key = `ZENOX-V3-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    const data = readData();

    const newKey = {
        key: key,
        deviceId: key,
        createdAt: new Date().toISOString(),
        expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString() : null,
        isActive: true,
        usageCount: 0,
        maxUsage: maxUsage,
        assignedTo: null,
        role: role
    };

    data.accessKeys.push(newKey);
    writeData(data);

    res.json({ success: true, key: newKey });
});

// ---------- ADMIN: REVOKE KEY ----------
app.delete('/api/admin/keys/:key', verifyToken, verifyAdmin, (req, res) => {
    const { key } = req.params;
    const data = readData();
    const index = data.accessKeys.findIndex(k => k.key === key);
    if (index === -1) {
        return res.status(404).json({ error: 'Key not found' });
    }
    data.accessKeys[index].isActive = false;
    writeData(data);
    res.json({ success: true });
});

// ---------- ADMIN: TOGGLE USER ----------
app.post('/api/admin/users/:id/toggle', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const data = readData();
    const user = data.users.find(u => u.id === id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    user.isActive = !user.isActive;
    writeData(data);
    res.json({ success: true, isActive: user.isActive });
});

// ---------- ADMIN: DELETE USER ----------
app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const data = readData();
    data.users = data.users.filter(u => u.id !== id);
    writeData(data);
    res.json({ success: true });
});

// ---------- HEALTH ----------
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ ZENOX SECURE V3 Server running on port ${PORT}`);
    console.log(`🔐 https://zenox-secure-v3.onrender.com`);
});
