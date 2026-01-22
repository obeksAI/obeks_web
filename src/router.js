import { hash, compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Static file serving
  if (path.startsWith('/public/') || path.endsWith('.css') || path.endsWith('.js') || path.endsWith('.png') || path.endsWith('.jpg')) {
    return env.ASSETS.fetch(request);
  }
  
  // API Routes
  if (path.startsWith('/api/')) {
    return handleAPI(request, env, ctx);
  }
  
  // HTML Pages
  return handlePages(request, env, ctx);
}

async function handleAPI(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  try {
    // Auth routes (no authentication required)
    if (path === '/api/auth/register' && request.method === 'POST') {
      return await handleRegister(request, env);
    }
    if (path === '/api/auth/login' && request.method === 'POST') {
      return await handleLogin(request, env);
    }
    
    // Verify JWT for protected routes
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }
    
    const token = authHeader.split(' ')[1];
    let user;
    try {
      user = verify(token, env.JWT_SECRET);
    } catch (err) {
      return jsonResponse({ error: 'Invalid token' }, 401);
    }
    
    // Protected API routes
    switch (path) {
      case '/api/user/profile':
        return await handleUserProfile(request, env, user);
      case '/api/agents':
        return await handleAgents(request, env, user);
      case '/api/agents/telegram':
        return await handleTelegramAgent(request, env, user);
      case '/api/chat/history':
        return await handleChatHistory(request, env, user);
      case '/api/api-keys':
        return await handleAPIKeys(request, env, user);
      case '/api/vector-dbs':
        return await handleVectorDBs(request, env, user);
      case '/api/platform/keys':
        return await handlePlatformKeys(request, env, user);
      default:
        return jsonResponse({ error: 'Not found' }, 404);
    }
  } catch (error) {
    console.error('API Error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handlePages(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  let page = 'dashboard';
  if (path === '/login') page = 'login';
  else if (path === '/register') page = 'register';
  else if (path === '/') page = 'dashboard';
  else if (path === '/agents') page = 'agents';
  else if (path === '/api-keys') page = 'api-keys';
  else if (path === '/vector-dbs') page = 'vector-dbs';
  else if (path === '/api-docs') page = 'api-docs';
  
  const html = await renderPage(page);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' },
  });
}

// Authentication handlers
async function handleRegister(request, env) {
  const { email, username, password } = await request.json();
  
  // Check if user exists
  const existingUser = await env.DB.prepare(
    'SELECT id FROM users WHERE email = ? OR username = ?'
  ).bind(email, username).first();
  
  if (existingUser) {
    return jsonResponse({ error: 'User already exists' }, 400);
  }
  
  // Hash password
  const passwordHash = await hash(password, 10);
  const userId = uuidv4();
  const apiKey = `obks_${uuidv4().replace(/-/g, '')}`;
  
  // Create user
  await env.DB.prepare(
    'INSERT INTO users (id, email, username, password_hash, api_key) VALUES (?, ?, ?, ?, ?)'
  ).bind(userId, email, username, passwordHash, apiKey).run();
  
  // Generate JWT
  const token = sign(
    { id: userId, email, username },
    env.JWT_SECRET,
    { expiresIn: env.SESSION_DURATION }
  );
  
  return jsonResponse({
    token,
    user: { id: userId, email, username, apiKey }
  });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  
  // Get user
  const user = await env.DB.prepare(
    'SELECT id, email, username, password_hash FROM users WHERE email = ?'
  ).bind(email).first();
  
  if (!user) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }
  
  // Verify password
  const isValid = await compare(password, user.password_hash);
  if (!isValid) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }
  
  // Generate JWT
  const token = sign(
    { id: user.id, email: user.email, username: user.username },
    env.JWT_SECRET,
    { expiresIn: env.SESSION_DURATION }
  );
  
  return jsonResponse({
    token,
    user: { id: user.id, email: user.email, username: user.username }
  });
}

// Telegram Agent Handler
async function handleTelegramAgent(request, env, user) {
  if (request.method === 'POST') {
    const { name, instructions, telegram_token } = await request.json();
    const agentId = uuidv4();
    
    await env.DB.prepare(
      `INSERT INTO ai_agents (id, user_id, name, agent_type, configuration, telegram_bot_token, instructions, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      agentId,
      user.id,
      name,
      'telegram_bot',
      JSON.stringify({ instructions, model: env.DEFAULT_AI_MODEL }),
      telegram_token,
      instructions,
      'active'
    ).run();
    
    // Start the Telegram bot webhook
    ctx.waitUntil(setupTelegramWebhook(telegram_token, env, agentId));
    
    return jsonResponse({ success: true, agentId });
  }
  
  // GET - List agents
  const agents = await env.DB.prepare(
    'SELECT id, name, agent_type, status, created_at FROM ai_agents WHERE user_id = ?'
  ).bind(user.id).all();
  
  return jsonResponse({ agents: agents.results });
}

// Chat History Handler
async function handleChatHistory(request, env, user) {
  const url = new URL(request.url);
  const agentId = url.searchParams.get('agent_id');
  
  if (!agentId) {
    const history = await env.DB.prepare(
      `SELECT ch.*, a.name as agent_name 
       FROM agent_chat_history ch
       JOIN ai_agents a ON ch.agent_id = a.id
       WHERE a.user_id = ?
       ORDER BY ch.timestamp DESC
       LIMIT 50`
    ).bind(user.id).all();
    
    return jsonResponse({ history: history.results });
  }
  
  const history = await env.DB.prepare(
    'SELECT * FROM agent_chat_history WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 100'
  ).bind(agentId).all();
  
  return jsonResponse({ history: history.results });
}

// API Keys Handler
async function handleAPIKeys(request, env, user) {
  if (request.method === 'POST') {
    const { platform, api_key } = await request.json();
    const keyId = uuidv4();
    
    await env.DB.prepare(
      'INSERT INTO user_api_keys (id, user_id, platform, api_key) VALUES (?, ?, ?, ?)'
    ).bind(keyId, user.id, platform, api_key).run();
    
    return jsonResponse({ success: true, keyId });
  }
  
  if (request.method === 'DELETE') {
    const { id } = await request.json();
    await env.DB.prepare('DELETE FROM user_api_keys WHERE id = ? AND user_id = ?')
      .bind(id, user.id).run();
    
    return jsonResponse({ success: true });
  }
  
  const keys = await env.DB.prepare(
    'SELECT id, platform, created_at FROM user_api_keys WHERE user_id = ?'
  ).bind(user.id).all();
  
  return jsonResponse({ keys: keys.results });
}

// Platform API Keys Handler
async function handlePlatformKeys(request, env, user) {
  if (request.method === 'POST') {
    const { key_name, permissions } = await request.json();
    const keyId = uuidv4();
    const apiKey = `obks_plat_${uuidv4().replace(/-/g, '')}`;
    
    await env.DB.prepare(
      `INSERT INTO platform_api_keys (id, user_id, key_name, api_key, permissions, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      keyId,
      user.id,
      key_name,
      apiKey,
      JSON.stringify(permissions || ['read', 'chat']),
      new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    ).run();
    
    return jsonResponse({ success: true, apiKey });
  }
  
  const keys = await env.DB.prepare(
    'SELECT id, key_name, api_key, permissions, created_at, expires_at FROM platform_api_keys WHERE user_id = ?'
  ).bind(user.id).all();
  
  return jsonResponse({ keys: keys.results });
}

// Vector Databases Handler
async function handleVectorDBs(request, env, user) {
  if (request.method === 'POST') {
    const { name, description, embeddings_provider } = await request.json();
    const dbId = uuidv4();
    
    await env.DB.prepare(
      `INSERT INTO vector_databases (id, user_id, name, description, embeddings_provider)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(dbId, user.id, name, description, embeddings_provider || 'openai').run();
    
    return jsonResponse({ success: true, dbId });
  }
  
  const dbs = await env.DB.prepare(
    'SELECT id, name, description, embeddings_provider, status, created_at FROM vector_databases WHERE user_id = ?'
  ).bind(user.id).all();
  
  return jsonResponse({ databases: dbs.results });
}

// Helper function to setup Telegram webhook
async function setupTelegramWebhook(token, env, agentId) {
  const webhookUrl = `https://${new URL(env.WORKER_URL).hostname}/api/webhook/telegram/${agentId}`;
  
  const response = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: webhookUrl })
  });
  
  return response.ok;
}

// Telegram Webhook Handler (add to router)
async function handleTelegramWebhook(request, env, agentId) {
  const update = await request.json();
  
  // Get agent configuration
  const agent = await env.DB.prepare(
    'SELECT instructions, telegram_bot_token, configuration FROM ai_agents WHERE id = ?'
  ).bind(agentId).first();
  
  if (!agent) {
    return new Response('Agent not found', { status: 404 });
  }
  
  // Get user's OpenRouter API key
  const apiKey = await env.DB.prepare(
    'SELECT api_key FROM user_api_keys WHERE user_id = (SELECT user_id FROM ai_agents WHERE id = ?) AND platform = ?'
  ).bind(agentId, 'openrouter').first();
  
  if (!apiKey) {
    return new Response('API key not found', { status: 400 });
  }
  
  // Process message with OpenRouter
  const aiResponse = await callOpenRouter(
    update.message.text,
    agent.instructions,
    apiKey.api_key,
    env.DEFAULT_AI_MODEL
  );
  
  // Save to chat history
  await env.DB.prepare(
    'INSERT INTO agent_chat_history (id, agent_id, user_message, ai_response) VALUES (?, ?, ?, ?)'
  ).bind(uuidv4(), agentId, update.message.text, aiResponse).run();
  
  // Send response back to Telegram
  await fetch(`https://api.telegram.org/bot${agent.telegram_bot_token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: update.message.chat.id,
      text: aiResponse
    })
  });
  
  return new Response('OK');
}

async function callOpenRouter(message, instructions, apiKey, model) {
  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: model,
      messages: [
        { role: 'system', content: instructions },
        { role: 'user', content: message }
      ]
    })
  });
  
  const data = await response.json();
  return data.choices[0].message.content;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function renderPage(page) {
  // This would be your HTML template rendering logic
  // For brevity, I'll show a simplified version
  const baseHTML = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Obeks AI - Private Management</title>
    <link rel="stylesheet" href="/public/css/styles.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  </head>
  <body>
    <div id="app"></div>
    <script src="/public/js/app.js"></script>
  </body>
  </html>`;
  
  return baseHTML;
}
