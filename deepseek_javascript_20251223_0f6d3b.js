const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

// ========== CONFIGURATION ==========
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_ALGORITHM = 'HS256';
const ACCESS_TOKEN_EXPIRE_MINUTES = 30;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('base64');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========== DATABASE CONNECTION ==========
let db;
const mongoClient = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');

async function connectDB() {
    try {
        await mongoClient.connect();
        db = mongoClient.db('recovery_system');
        console.log('✅ MongoDB connected');
        
        // Create indexes
        await db.collection('users').createIndex({ username: 1 }, { unique: true });
        await db.collection('users').createIndex({ device_id: 1 }, { unique: true });
        await db.collection('sessions').createIndex({ token: 1 }, { unique: true });
        await db.collection('sessions').createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
        await db.collection('file_metadata').createIndex({ user_id: 1, path: 1 });
    } catch (err) {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    }
}

// ========== UTILITY FUNCTIONS ==========
function createAccessToken(userId) {
    return jwt.sign(
        { sub: userId, type: 'access' },
        JWT_SECRET,
        { algorithm: JWT_ALGORITHM, expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m` }
    );
}

function createRefreshToken(userId) {
    return jwt.sign(
        { sub: userId, type: 'refresh' },
        JWT_SECRET,
        { algorithm: JWT_ALGORITHM, expiresIn: '7d' }
    );
}

function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'base64'), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
        iv: iv.toString('hex'),
        encrypted: encrypted,
        authTag: authTag.toString('hex')
    };
}

function decryptData(encryptedData) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(ENCRYPTION_KEY, 'base64'),
        Buffer.from(encryptedData.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ========== AUTH MIDDLEWARE ==========
async function authenticate(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        const deviceId = req.headers['x-device-id'];
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        
        if (!deviceId) {
            return res.status(401).json({ error: 'Device ID required' });
        }
        
        const token = authHeader.split(' ')[1];
        
        // Verify JWT
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        
        if (decoded.type !== 'access') {
            return res.status(401).json({ error: 'Invalid token type' });
        }
        
        // Validate session in database
        const session = await db.collection('sessions').findOne({
            token: token,
            device_id: deviceId,
            is_valid: true,
            expires_at: { $gt: new Date() }
        });
        
        if (!session) {
            return res.status(401).json({ error: 'Session expired or invalid' });
        }
        
        // Update session last active
        await db.collection('sessions').updateOne(
            { _id: session._id },
            { $set: { last_active: new Date() } }
        );
        
        // Get user
        const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.sub) });
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        req.user = {
            id: user._id.toString(),
            username: user.username,
            device_id: user.device_id
        };
        
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ error: 'Authentication failed' });
    }
}

// ========== ROUTES ==========

// Health Check
app.get('/health', async (req, res) => {
    try {
        await db.command({ ping: 1 });
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: 'connected'
        });
    } catch (err) {
        res.status(500).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            database: 'disconnected'
        });
    }
});

// Register
app.post('/register', async (req, res) => {
    try {
        const { username, password, device_id } = req.body;
        
        // Validation
        if (!username || username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        if (!password || password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        if (!device_id || device_id.length < 10) {
            return res.status(400).json({ error: 'Device ID must be at least 10 characters' });
        }
        
        // Check existing user
        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Check existing device
        const existingDevice = await db.collection('users').findOne({ device_id });
        if (existingDevice) {
            return res.status(400).json({ error: 'Device already registered' });
        }
        
        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);
        
        // Create user
        const user = {
            username,
            password_hash: passwordHash,
            device_id,
            created_at: new Date(),
            last_login: null,
            is_active: true
        };
        
        const result = await db.collection('users').insertOne(user);
        
        res.json({
            message: 'Registration successful',
            user_id: result.insertedId.toString()
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { username, password, device_id } = req.body;
        
        // Find user
        const user = await db.collection('users').findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify device
        if (user.device_id !== device_id) {
            return res.status(401).json({ error: 'Device not authorized' });
        }
        
        // Update last login
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { last_login: new Date() } }
        );
        
        // Create tokens
        const accessToken = createAccessToken(user._id.toString());
        const refreshToken = createRefreshToken(user._id.toString());
        
        // Create session
        const session = {
            user_id: user._id,
            token: accessToken,
            device_id,
            ip_address: req.ip,
            created_at: new Date(),
            expires_at: new Date(Date.now() + ACCESS_TOKEN_EXPIRE_MINUTES * 60 * 1000),
            last_active: new Date(),
            is_valid: true
        };
        
        await db.collection('sessions').insertOne(session);
        
        res.json({
            access_token: accessToken,
            token_type: 'bearer',
            expires_in: ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token: refreshToken
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout
app.post('/logout', authenticate, async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        await db.collection('sessions').updateOne(
            { token },
            { $set: { is_valid: false } }
        );
        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Refresh Token
app.post('/refresh', async (req, res) => {
    try {
        const { refresh_token, device_id } = req.body;
        
        if (!refresh_token || !device_id) {
            return res.status(400).json({ error: 'Refresh token and device ID required' });
        }
        
        // Verify refresh token
        let decoded;
        try {
            decoded = jwt.verify(refresh_token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
        } catch (err) {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }
        
        if (decoded.type !== 'refresh') {
            return res.status(401).json({ error: 'Invalid token type' });
        }
        
        // Get user
        const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.sub) });
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        // Create new access token
        const newAccessToken = createAccessToken(user._id.toString());
        
        // Create new session
        const session = {
            user_id: user._id,
            token: newAccessToken,
            device_id,
            ip_address: '0.0.0.0',
            created_at: new Date(),
            expires_at: new Date(Date.now() + ACCESS_TOKEN_EXPIRE_MINUTES * 60 * 1000),
            last_active: new Date(),
            is_valid: true
        };
        
        await db.collection('sessions').insertOne(session);
        
        res.json({
            access_token: newAccessToken,
            token_type: 'bearer',
            expires_in: ACCESS_TOKEN_EXPIRE_MINUTES * 60
        });
    } catch (err) {
        console.error('Refresh error:', err);
        res.status(500).json({ error: 'Token refresh failed' });
    }
});

// ========== PROTECTED ROUTES ==========

// File Metadata Upload
app.post('/files/upload-metadata', authenticate, async (req, res) => {
    try {
        const { filename, path, size_bytes, mime_type, category } = req.body;
        
        // Generate file encryption key
        const fileKey = crypto.randomBytes(32);
        const encryptedKey = encryptData(fileKey.toString('base64'));
        
        // Store metadata
        const metadata = {
            user_id: new ObjectId(req.user.id),
            filename,
            path,
            size_bytes,
            mime_type,
            category,
            encrypted_key: encryptedKey,
            created_at: new Date(),
            last_accessed: new Date(),
            access_count: 0,
            is_available: true
        };
        
        const result = await db.collection('file_metadata').insertOne(metadata);
        
        res.json({
            file_id: result.insertedId.toString(),
            message: 'File metadata stored',
            encryption_key: fileKey.toString('base64')
        });
    } catch (err) {
        console.error('File metadata upload error:', err);
        res.status(500).json({ error: 'Failed to upload file metadata' });
    }
});

// List Files
app.get('/files/list', authenticate, async (req, res) => {
    try {
        const { category } = req.query;
        const limit = parseInt(req.query.limit) || 100;
        const skip = parseInt(req.query.skip) || 0;
        
        const query = {
            user_id: new ObjectId(req.user.id),
            is_available: true
        };
        
        if (category) {
            query.category = category;
        }
        
        const files = await db.collection('file_metadata')
            .find(query)
            .sort({ last_accessed: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();
        
        // Remove encryption key from response
        const safeFiles = files.map(file => {
            const { encrypted_key, ...safeFile } = file;
            return {
                ...safeFile,
                _id: file._id.toString()
            };
        });
        
        res.json({
            files: safeFiles,
            total: safeFiles.length,
            category: category || 'all'
        });
    } catch (err) {
        console.error('List files error:', err);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// Generate Download URL
app.get('/files/:fileId/download-url', authenticate, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        
        const file = await db.collection('file_metadata').findOne({
            _id: new ObjectId(fileId),
            user_id: new ObjectId(req.user.id),
            is_available: true
        });
        
        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        // Update access stats
        await db.collection('file_metadata').updateOne(
            { _id: new ObjectId(fileId) },
            {
                $set: { last_accessed: new Date() },
                $inc: { access_count: 1 }
            }
        );
        
        // Create download token
        const downloadToken = jwt.sign(
            {
                file_id: fileId,
                user_id: req.user.id,
                purpose: 'download'
            },
            JWT_SECRET,
            { algorithm: JWT_ALGORITHM, expiresIn: '5m' }
        );
        
        res.json({
            download_token: downloadToken,
            expires_in: 300,
            filename: file.filename,
            size_bytes: file.size_bytes
        });
    } catch (err) {
        console.error('Download URL error:', err);
        res.status(500).json({ error: 'Failed to generate download URL' });
    }
});

// Create Recovery Action
app.post('/actions/create', authenticate, async (req, res) => {
    try {
        const { action_type, parameters, requires_confirmation = true } = req.body;
        
        const action = {
            user_id: new ObjectId(req.user.id),
            action_type,
            parameters,
            initiated_by: 'remote',
            status: requires_confirmation ? 'pending' : 'approved',
            result: null,
            timestamp: new Date(),
            completed_at: null,
            requires_confirmation,
            confirmed: false
        };
        
        const result = await db.collection('recovery_actions').insertOne(action);
        
        res.json({
            action_id: result.insertedId.toString(),
            requires_confirmation,
            message: 'Action created successfully'
        });
    } catch (err) {
        console.error('Create action error:', err);
        res.status(500).json({ error: 'Failed to create action' });
    }
});

// Get Pending Actions
app.get('/actions/pending', authenticate, async (req, res) => {
    try {
        const actions = await db.collection('recovery_actions')
            .find({
                user_id: new ObjectId(req.user.id),
                requires_confirmation: true,
                confirmed: false,
                status: 'pending'
            })
            .sort({ timestamp: 1 })
            .limit(10)
            .toArray();
        
        const formattedActions = actions.map(action => ({
            ...action,
            _id: action._id.toString()
        }));
        
        res.json({
            actions: formattedActions,
            count: formattedActions.length
        });
    } catch (err) {
        console.error('Get pending actions error:', err);
        res.status(500).json({ error: 'Failed to get pending actions' });
    }
});

// Confirm Action
app.post('/actions/confirm', authenticate, async (req, res) => {
    try {
        const { action_id, confirm } = req.body;
        
        if (confirm) {
            const result = await db.collection('recovery_actions').updateOne(
                {
                    _id: new ObjectId(action_id),
                    user_id: new ObjectId(req.user.id),
                    requires_confirmation: true
                },
                {
                    $set: {
                        confirmed: true,
                        status: 'confirmed'
                    }
                }
            );
            
            if (result.modifiedCount === 0) {
                return res.status(404).json({ error: 'Action not found or already processed' });
            }
            
            res.json({ message: 'Action confirmed', status: 'confirmed' });
        } else {
            await db.collection('recovery_actions').updateOne(
                { _id: new ObjectId(action_id) },
                { $set: { status: 'denied' } }
            );
            res.json({ message: 'Action denied', status: 'denied' });
        }
    } catch (err) {
        console.error('Confirm action error:', err);
        res.status(500).json({ error: 'Failed to confirm action' });
    }
});

// Device Status
app.get('/device/status', authenticate, async (req, res) => {
    try {
        const pendingActions = await db.collection('recovery_actions')
            .find({
                user_id: new ObjectId(req.user.id),
                requires_confirmation: true,
                confirmed: false,
                status: 'pending'
            })
            .count();
        
        res.json({
            device_id: req.user.device_id,
            username: req.user.username,
            pending_actions: pendingActions,
            last_update: new Date().toISOString(),
            status: 'online'
        });
    } catch (err) {
        console.error('Device status error:', err);
        res.status(500).json({ error: 'Failed to get device status' });
    }
});

// Device Heartbeat
app.post('/device/heartbeat', authenticate, async (req, res) => {
    try {
        const { battery_level, storage_free, network_status } = req.body;
        
        // Log heartbeat
        await db.collection('device_heartbeats').insertOne({
            user_id: new ObjectId(req.user.id),
            device_id: req.user.device_id,
            timestamp: new Date(),
            battery_level,
            storage_free,
            network_status
        });
        
        // Check for pending actions
        const pendingActions = await db.collection('recovery_actions')
            .find({
                user_id: new ObjectId(req.user.id),
                requires_confirmation: true,
                confirmed: false,
                status: 'pending'
            })
            .project({ _id: 1, action_type: 1 })
            .toArray();
        
        res.json({
            pending_actions: pendingActions.map(a => ({
                id: a._id.toString(),
                type: a.action_type
            })),
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('Heartbeat error:', err);
        res.status(500).json({ error: 'Failed to process heartbeat' });
    }
});

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ========== START SERVER ==========
async function startServer() {
    await connectDB();
    
    app.listen(PORT, () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`📚 API Documentation: http://localhost:${PORT}/health`);
    });
}

startServer().catch(err => {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
});

module.exports = app; // For testing