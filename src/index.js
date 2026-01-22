// index.js - Cloudflare Worker with D1 Database
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // Set up basic headers
      const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      };

      // Handle CORS preflight
      if (method === 'OPTIONS') {
        return new Response(null, { headers });
      }

      // Simple JWT utility
      const jwt = {
        sign: (payload) => btoa(JSON.stringify(payload)),
        verify: (token) => JSON.parse(atob(token))
      };

      // Initialize database tables if they don't exist
      await initDatabase(env.DB);

      // Route handling
      if (path === '/' || path === '') {
        return Response.redirect('https://yourdomain.com/login', 302);
      }

      if (path === '/api/login' && method === 'POST') {
        return handleLogin(request, env);
      }

      if (path === '/api/signup' && method === 'POST') {
        return handleSignup(request, env);
      }

      if (path === '/api/dashboard') {
        return handleDashboard(request, env);
      }

      if (path === '/api/ai/add' && method === 'POST') {
        return handleAddAI(request, env);
      }

      if (path.startsWith('/api/ai/') && method === 'DELETE') {
        return handleDeleteAI(request, env, path);
      }

      if (path === '/api/database/upload' && method === 'POST') {
        return handleDatabaseUpload(request, env);
      }

      if (path === '/api/settings/api' && method === 'POST') {
        return handleSaveAPIKey(request, env);
      }

      if (path === '/webhook/whatsapp' && method === 'POST') {
        return handleWhatsAppWebhook(request, env);
      }

      if (path === '/webhook/telegram' && method === 'POST') {
        return handleTelegramWebhook(request, env);
      }

      if (path === '/webhook/facebook' && method === 'POST') {
        return handleFacebookWebhook(request, env);
      }

      // Default response for inactive routes
      return new Response(
        JSON.stringify({
          message: 'Route not active yet. Coming soon!',
          status: 'under_development',
          available_routes: [
            '/api/login',
            '/api/signup',
            '/api/dashboard',
            '/api/ai/add',
            '/api/database/upload',
            '/webhook/whatsapp',
            '/webhook/telegram',
            '/webhook/facebook'
          ]
        }),
        { headers, status: 200 }
      );

    } catch (error) {
      console.error('Error:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error.message
        }),
        {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        }
      );
    }
  }
};

// Database initialization
async function initDatabase(db) {
  try {
    // Users table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        business_name TEXT NOT NULL,
        country_code TEXT,
        whatsapp_number TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'active'
      )
    `);

    // AI Workforce table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS ai_workforce (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ai_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        business_info TEXT,
        service_name TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // API Keys table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        service_name TEXT NOT NULL,
        api_key TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // WhatsApp Bots table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS whatsapp_bots (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ai_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        phone_number TEXT NOT NULL,
        account_sid TEXT,
        auth_token TEXT,
        access_token TEXT,
        phone_number_id TEXT,
        wati_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Telegram Bots table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS telegram_bots (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ai_id TEXT NOT NULL,
        bot_token TEXT NOT NULL,
        bot_username TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // User Databases table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS user_databases (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        file_type TEXT NOT NULL,
        data TEXT, -- JSON stored as TEXT
        record_count INTEGER DEFAULT 0,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Chat History table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS chat_history (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ai_id TEXT NOT NULL,
        platform TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        message TEXT NOT NULL,
        response TEXT NOT NULL,
        direction TEXT DEFAULT 'incoming',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Password hashing using native Web Crypto API
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifyPassword(password, hash) {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

// Helper to get user from JWT token
async function getUserFromRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);
  try {
    const payload = jwt.verify(token);
    
    const { results } = await env.DB.prepare(
      'SELECT * FROM users WHERE id = ?'
    ).bind(payload.userId).all();
    
    if (results.length === 0) {
      return null;
    }
    
    return results[0];
  } catch (error) {
    return null;
  }
}

// Route Handlers
async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const { email, password } = body;

    const { results } = await env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email).all();

    if (results.length === 0) {
      return new Response(
        JSON.stringify({ error: 'Invalid credentials' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const user = results[0];
    const isValid = await verifyPassword(password, user.password_hash);

    if (!isValid) {
      return new Response(
        JSON.stringify({ error: 'Invalid credentials' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Create JWT token
    const token = jwt.sign({
      userId: user.id,
      email: user.email,
      businessName: user.business_name,
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    });

    return new Response(
      JSON.stringify({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email,
          business_name: user.business_name
        }
      }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleSignup(request, env) {
  try {
    const body = await request.json();
    const { email, password, business_name, country_code, whatsapp_number } = body;

    // Check if user exists
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).all();

    if (existing.results.length > 0) {
      return new Response(
        JSON.stringify({ error: 'Email already registered' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Hash password
    const passwordHash = await hashPassword(password);
    const userId = crypto.randomUUID();

    // Insert user
    await env.DB.prepare(
      `INSERT INTO users (id, email, password_hash, business_name, country_code, whatsapp_number)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(userId, email, passwordHash, business_name, country_code, whatsapp_number).run();

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Account created successfully',
        userId
      }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleDashboard(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Get AI workforce
  const aiWorkforce = await env.DB.prepare(
    'SELECT * FROM ai_workforce WHERE user_id = ?'
  ).bind(user.id).all();

  // Get database count
  const dbCount = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM user_databases WHERE user_id = ?'
  ).bind(user.id).all();

  // Get chat history count
  const chatCount = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM chat_history WHERE user_id = ?'
  ).bind(user.id).all();

  // Count active AI
  const activeAICount = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM ai_workforce WHERE user_id = ? AND status = ?'
  ).bind(user.id, 'active').all();

  return new Response(
    JSON.stringify({
      user: {
        id: user.id,
        email: user.email,
        business_name: user.business_name
      },
      ai_workforce: aiWorkforce.results,
      statistics: {
        database_count: dbCount.results[0].count,
        chat_count: chatCount.results[0].count,
        active_ai_count: activeAICount.results[0].count
      }
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

async function handleAddAI(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    const body = await request.json();
    const { ai_id, name, description, business_info, service_name } = body;

    const aiRecordId = crypto.randomUUID();

    await env.DB.prepare(
      `INSERT INTO ai_workforce (id, user_id, ai_id, name, description, business_info, service_name)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(aiRecordId, user.id, ai_id, name, description, business_info, service_name).run();

    return new Response(
      JSON.stringify({
        success: true,
        message: 'AI added successfully',
        ai_id: aiRecordId
      }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleDeleteAI(request, env, path) {
  const user = await getUserFromRequest(request, env);
  if (!user) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const aiId = path.split('/').pop();

  // Check if AI belongs to user
  const aiCheck = await env.DB.prepare(
    'SELECT id FROM ai_workforce WHERE id = ? AND user_id = ?'
  ).bind(aiId, user.id).all();

  if (aiCheck.results.length === 0) {
    return new Response(
      JSON.stringify({ error: 'AI not found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // Delete the AI
  await env.DB.prepare(
    'DELETE FROM ai_workforce WHERE id = ?'
  ).bind(aiId).run();

  return new Response(
    JSON.stringify({
      success: true,
      message: 'AI deleted successfully'
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

async function handleDatabaseUpload(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    const formData = await request.formData();
    const file = formData.get('database_file');
    const dbName = formData.get('db_name');
    const description = formData.get('db_description');

    if (!file || !dbName) {
      return new Response(
        JSON.stringify({ error: 'File and database name are required' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const fileContent = await file.text();
    const fileType = file.name.split('.').pop().toLowerCase();
    let data;

    if (fileType === 'json') {
      data = JSON.parse(fileContent);
    } else if (fileType === 'csv') {
      const lines = fileContent.split('\n');
      const headers = lines[0].split(',');
      data = lines.slice(1).map(line => {
        const values = line.split(',');
        const obj = {};
        headers.forEach((header, index) => {
          obj[header.trim()] = values[index] ? values[index].trim() : '';
        });
        return obj;
      }).filter(obj => Object.keys(obj).length > 0);
    } else {
      return new Response(
        JSON.stringify({ error: 'Only JSON and CSV files are allowed' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const dbId = crypto.randomUUID();
    const recordCount = Array.isArray(data) ? data.length : 1;

    await env.DB.prepare(
      `INSERT INTO user_databases (id, user_id, name, description, file_type, data, record_count)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(dbId, user.id, dbName, description, fileType, JSON.stringify(data), recordCount).run();

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Database uploaded successfully',
        db_id: dbId,
        record_count: recordCount
      }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleSaveAPIKey(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    const body = await request.json();
    const { service_name, api_key } = body;

    // Check if key exists
    const existing = await env.DB.prepare(
      'SELECT id FROM api_keys WHERE user_id = ? AND service_name = ?'
    ).bind(user.id, service_name).all();

    const keyId = crypto.randomUUID();

    if (existing.results.length > 0) {
      // Update existing
      await env.DB.prepare(
        'UPDATE api_keys SET api_key = ? WHERE user_id = ? AND service_name = ?'
      ).bind(api_key, user.id, service_name).run();
    } else {
      // Insert new
      await env.DB.prepare(
        'INSERT INTO api_keys (id, user_id, service_name, api_key) VALUES (?, ?, ?, ?)'
      ).bind(keyId, user.id, service_name, api_key).run();
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: 'API key saved successfully'
      }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleWhatsAppWebhook(request, env) {
  if (request.method === 'GET') {
    // Webhook verification
    const url = new URL(request.url);
    const hubMode = url.searchParams.get('hub.mode');
    const hubToken = url.searchParams.get('hub.verify_token');
    const hubChallenge = url.searchParams.get('hub.challenge');

    const VERIFY_TOKEN = "obeksai123";

    if (hubMode === 'subscribe' && hubToken === VERIFY_TOKEN) {
      return new Response(hubChallenge, { status: 200 });
    } else {
      return new Response('Verification failed', { status: 403 });
    }
  }

  // POST: Handle incoming messages
  try {
    const body = await request.json();
    console.log('WhatsApp webhook received:', JSON.stringify(body, null, 2));

    // Process different providers (Meta, Twilio, WATI)
    let messageText = '';
    let senderNumber = '';

    // Meta format
    if (body.entry && body.entry[0]?.changes) {
      const change = body.entry[0].changes[0];
      if (change.field === 'messages' && change.value?.messages) {
        const message = change.value.messages[0];
        if (message.type === 'text') {
          messageText = message.text.body;
          senderNumber = message.from;
        }
      }
    }
    // Add other provider formats here (Twilio, WATI)

    if (messageText) {
      // Find the appropriate AI to respond
      // This is simplified - you'll need to implement your bot matching logic
      console.log(`Processing WhatsApp message: "${messageText}" from ${senderNumber}`);

      // Save to chat history
      await saveChatHistory({
        user_id: 'system',
        ai_id: 'whatsapp_bot',
        platform: 'whatsapp',
        sender_id: senderNumber,
        message: messageText,
        response: 'Message received',
        direction: 'incoming'
      }, env);
    }

    return new Response(
      JSON.stringify({ status: 'ok' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('WhatsApp webhook error:', error);
    return new Response(
      JSON.stringify({ status: 'ok' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleTelegramWebhook(request, env) {
  try {
    const body = await request.json();

    if (body.message && body.message.text) {
      const chatId = body.message.chat.id;
      const text = body.message.text;
      const senderId = body.message.from.id;

      console.log(`Telegram message: "${text}" from ${senderId}`);

      // Save to chat history
      await saveChatHistory({
        user_id: 'system',
        ai_id: 'telegram_bot',
        platform: 'telegram',
        sender_id: senderId.toString(),
        message: text,
        response: 'Message received',
        direction: 'incoming'
      }, env);

      // In a real implementation, you would:
      // 1. Find the bot configuration
      // 2. Generate AI response
      // 3. Send response back via Telegram API
    }

    return new Response(
      JSON.stringify({ status: 'ok' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Telegram webhook error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function handleFacebookWebhook(request, env) {
  if (request.method === 'GET') {
    // Webhook verification
    const url = new URL(request.url);
    const hubMode = url.searchParams.get('hub.mode');
    const hubToken = url.searchParams.get('hub.verify_token');
    const hubChallenge = url.searchParams.get('hub.challenge');

    const VERIFY_TOKEN = "facebook-verify-token";

    if (hubMode === 'subscribe' && hubToken === VERIFY_TOKEN) {
      return new Response(hubChallenge, { status: 200 });
    } else {
      return new Response('Verification failed', { status: 403 });
    }
  }

  // POST: Handle Facebook updates
  try {
    const body = await request.json();
    console.log('Facebook webhook received:', JSON.stringify(body, null, 2));

    // Process Facebook events
    if (body.entry && body.entry[0]?.changes) {
      for (const entry of body.entry) {
        for (const change of entry.changes) {
          console.log('Facebook change:', change);
          // Process different change types (comments, posts, etc.)
        }
      }
    }

    return new Response(
      JSON.stringify({ status: 'ok' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Facebook webhook error:', error);
    return new Response(
      JSON.stringify({ status: 'ok' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
  }
}

// Helper function to save chat history
async function saveChatHistory(chatData, env) {
  const chatId = crypto.randomUUID();
  
  await env.DB.prepare(
    `INSERT INTO chat_history (id, user_id, ai_id, platform, sender_id, message, response, direction, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    chatId,
    chatData.user_id,
    chatData.ai_id,
    chatData.platform,
    chatData.sender_id,
    chatData.message,
    chatData.response,
    chatData.direction || 'incoming',
    new Date().toISOString()
  ).run();
}
