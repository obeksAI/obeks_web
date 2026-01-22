// src/index.js - Main Worker with NO external dependencies
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // API Routes
    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env, ctx);
    }
    
    // Serve HTML page
    return new Response(getHTML(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
};

async function handleAPI(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  try {
    // Public routes
    if (path === '/api/auth/register' && request.method === 'POST') {
      return await handleRegister(request, env);
    }
    if (path === '/api/auth/login' && request.method === 'POST') {
      return await handleLogin(request, env);
    }
    
    // Verify token for protected routes
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }
    
    const token = authHeader.split(' ')[1];
    let user;
    try {
      user = await verifyToken(token, env.JWT_SECRET);
    } catch (err) {
      return jsonResponse({ error: 'Invalid token' }, 401);
    }
    
    // Protected routes
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
      case '/api/webhook/telegram':
        return await handleTelegramWebhook(request, env);
      default:
        return jsonResponse({ error: 'Not found' }, 404);
    }
  } catch (error) {
    console.error('API Error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

// Simple JWT implementation for Cloudflare Workers
async function signToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerEncoded = btoa(JSON.stringify(header));
  const payloadEncoded = btoa(JSON.stringify(payload));
  const signature = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(headerEncoded + '.' + payloadEncoded + secret)
  );
  const signatureEncoded = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
}

async function verifyToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  
  const signature = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(parts[0] + '.' + parts[1] + secret)
  );
  const signatureEncoded = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  if (signatureEncoded !== parts[2]) {
    throw new Error('Invalid signature');
  }
  
  return JSON.parse(atob(parts[1]));
}

// Password hashing using Web Crypto API
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

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
  const passwordHash = await hashPassword(password);
  const userId = crypto.randomUUID();
  const apiKey = `obks_${crypto.randomUUID().replace(/-/g, '')}`;
  
  // Create user
  await env.DB.prepare(
    'INSERT INTO users (id, email, username, password_hash, api_key) VALUES (?, ?, ?, ?, ?)'
  ).bind(userId, email, username, passwordHash, apiKey).run();
  
  // Generate JWT
  const token = await signToken(
    { id: userId, email, username },
    env.JWT_SECRET
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
  const hashedPassword = await hashPassword(password);
  if (hashedPassword !== user.password_hash) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }
  
  // Generate JWT
  const token = await signToken(
    { id: user.id, email: user.email, username: user.username },
    env.JWT_SECRET
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
    const agentId = crypto.randomUUID();
    
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

async function setupTelegramWebhook(token, env, agentId) {
  const workerUrl = `https://${env.WORKER_NAME}.${env.WORKER_DOMAIN}/api/webhook/telegram/${agentId}`;
  
  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: workerUrl })
    });
    return response.ok;
  } catch (error) {
    console.error('Failed to setup Telegram webhook:', error);
    return false;
  }
}

async function handleTelegramWebhook(request, env) {
  const url = new URL(request.url);
  const agentId = url.pathname.split('/').pop();
  
  try {
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
    
    // Call OpenRouter API
    const aiResponse = await callOpenRouter(
      update.message.text,
      agent.instructions,
      apiKey.api_key,
      env.DEFAULT_AI_MODEL
    );
    
    // Save chat history
    await env.DB.prepare(
      'INSERT INTO agent_chat_history (id, agent_id, user_message, ai_response) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), agentId, update.message.text, aiResponse).run();
    
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
  } catch (error) {
    console.error('Telegram webhook error:', error);
    return new Response('Error', { status: 500 });
  }
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
  return data.choices?.[0]?.message?.content || 'No response from AI';
}

// Other handlers (simplified versions)
async function handleAPIKeys(request, env, user) {
  if (request.method === 'POST') {
    const { platform, api_key } = await request.json();
    const keyId = crypto.randomUUID();
    
    await env.DB.prepare(
      'INSERT INTO user_api_keys (id, user_id, platform, api_key) VALUES (?, ?, ?, ?)'
    ).bind(keyId, user.id, platform, api_key).run();
    
    return jsonResponse({ success: true, keyId });
  }
  
  const keys = await env.DB.prepare(
    'SELECT id, platform, created_at FROM user_api_keys WHERE user_id = ?'
  ).bind(user.id).all();
  
  return jsonResponse({ keys: keys.results });
}

async function handlePlatformKeys(request, env, user) {
  if (request.method === 'POST') {
    const { key_name, permissions } = await request.json();
    const keyId = crypto.randomUUID();
    const apiKey = `obks_plat_${crypto.randomUUID().replace(/-/g, '')}`;
    
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

async function handleVectorDBs(request, env, user) {
  if (request.method === 'POST') {
    const { name, description, embeddings_provider } = await request.json();
    const dbId = crypto.randomUUID();
    
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

// Helper functions
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Obeks AI - Private Management</title>
    <style>
        :root {
            --primary-blue: #0066FF;
            --primary-blue-dark: #0052CC;
            --primary-blue-light: #4D94FF;
            --dark-bg: #0A0F1C;
            --dark-card: #121A2F;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--dark-bg);
            color: white;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .glass-card {
            background: rgba(18, 26, 47, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            border: 1px solid rgba(77, 148, 255, 0.2);
            padding: 24px;
            margin-bottom: 20px;
        }
        
        .btn {
            background: var(--primary-blue);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn:hover {
            background: var(--primary-blue-dark);
        }
        
        .input-field {
            width: 100%;
            padding: 12px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(77, 148, 255, 0.3);
            border-radius: 8px;
            color: white;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="glass-card">
            <h1>Obeks AI</h1>
            <p>AI Agent Management Platform</p>
            <div id="app">
                <h2>Welcome to Obeks AI</h2>
                <p>Please use the API to interact with the platform.</p>
                <p>API Base URL: <code>/api/</code></p>
            </div>
        </div>
    </div>
    <script>
        // Simple frontend logic
        const token = localStorage.getItem('token');
        
        if (token) {
            // User is logged in
            fetch('/api/user/profile', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('app').innerHTML = \`
                    <h2>Welcome, \${data.user?.username || 'User'}!</h2>
                    <p>Your dashboard is ready.</p>
                    <button onclick="logout()" class="btn">Logout</button>
                \`;
            })
            .catch(() => {
                localStorage.removeItem('token');
                location.reload();
            });
        } else {
            // Show login/register
            document.getElementById('app').innerHTML = \`
                <div id="auth-forms">
                    <h3>Login</h3>
                    <input type="email" id="login-email" class="input-field" placeholder="Email">
                    <input type="password" id="login-password" class="input-field" placeholder="Password">
                    <button onclick="login()" class="btn">Login</button>
                    
                    <h3 style="margin-top: 30px;">Register</h3>
                    <input type="text" id="reg-username" class="input-field" placeholder="Username">
                    <input type="email" id="reg-email" class="input-field" placeholder="Email">
                    <input type="password" id="reg-password" class="input-field" placeholder="Password">
                    <button onclick="register()" class="btn">Register</button>
                </div>
            \`;
        }
        
        async function login() {
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            
            const data = await res.json();
            
            if (res.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                location.reload();
            } else {
                alert(data.error || 'Login failed');
            }
        }
        
        async function register() {
            const username = document.getElementById('reg-username').value;
            const email = document.getElementById('reg-email').value;
            const password = document.getElementById('reg-password').value;
            
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await res.json();
            
            if (res.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                location.reload();
            } else {
                alert(data.error || 'Registration failed');
            }
        }
        
        function logout() {
            localStorage.clear();
            location.reload();
        }
    </script>
</body>
</html>`;
}
