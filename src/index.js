// src/index.js - Main Worker with NO external dependencies
// Update your main fetch handler:
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Handle OPTIONS for CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        }
      });
    }
    
    // API Routes
    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env, ctx);
    }
    
    // Serve Dashboard HTML for root path
    if (url.pathname === '/' || url.pathname === '/dashboard') {
      // Check if user is logged in
      const authHeader = request.headers.get('Authorization');
      let user = null;
      
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
          user = await verifySimpleToken(token, env.JWT_SECRET);
        } catch (err) {
          // Token invalid, show login
        }
      }
      
      // Check for token in cookie or localStorage via JavaScript
      const html = getDashboardHTML();
      return new Response(html, {
        headers: { 
          'Content-Type': 'text/html',
          'Cache-Control': 'no-cache'
        }
      });
    }
    
    // Login page
    if (url.pathname === '/login' || url.pathname === '/register') {
      const html = getLoginHTML();
      return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    // 404 for other paths
    return new Response('Not Found', { status: 404 });
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
      // In your handleAPI function, add:
case '/api/dashboard':
  return await handleDashboard(request, env, user);
case '/api/agents/create':
  return await handleCreateAgent(request, env, user);

case '/api/agents/telegram/setup':
  return await handleTelegramSetup(request, env, user);

case '/api/agents/:id':
  if (request.method === 'DELETE') {
    return await handleDeleteAgent(request, env, user);
  }
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

// Create Agent handler
async function handleCreateAgent(request, env, user) {
  const { ai_type, name, description } = await request.json();
  const agentId = crypto.randomUUID();
  
  await env.DB.prepare(
    'INSERT INTO ai_agents (id, user_id, name, agent_type, status) VALUES (?, ?, ?, ?, ?)'
  ).bind(agentId, user.id, name, ai_type, 'inactive').run();
  
  return jsonResponse({ 
    success: true, 
    agent_id: agentId,
    message: 'Agent created successfully'
  });
}

// Telegram Setup handler
async function handleTelegramSetup(request, env, user) {
  const { agent_id, telegram_token } = await request.json();
  
  await env.DB.prepare(
    'UPDATE ai_agents SET telegram_bot_token = ?, status = ? WHERE id = ? AND user_id = ?'
  ).bind(telegram_token, 'active', agent_id, user.id).run();
  
  // Setup webhook
  const webhookUrl = `https://${env.WORKER_DOMAIN}/api/webhook/telegram/${agent_id}`;
  await fetch(`https://api.telegram.org/bot${telegram_token}/setWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: webhookUrl })
  });
  
  return jsonResponse({ 
    success: true,
    message: 'Telegram bot configured successfully'
  });
}

// Delete Agent handler
async function handleDeleteAgent(request, env, user) {
  const url = new URL(request.url);
  const agentId = url.pathname.split('/').pop();
  
  await env.DB.prepare(
    'DELETE FROM ai_agents WHERE id = ? AND user_id = ?'
  ).bind(agentId, user.id).run();
  
  return jsonResponse({ success: true, message: 'Agent deleted successfully' });
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

// Dashboard handler
async function handleDashboard(request, env, user) {
  try {
    // Get user's agents
    const agents = await env.DB.prepare(
      'SELECT id, name, agent_type, status, created_at FROM ai_agents WHERE user_id = ?'
    ).bind(user.id).all();
    
    // Get chat history count
    const chatCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM agent_chat_history WHERE agent_id IN (SELECT id FROM ai_agents WHERE user_id = ?)'
    ).bind(user.id).first();
    
    // Get vector databases count
    const dbCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM vector_databases WHERE user_id = ?'
    ).bind(user.id).first();
    
    // Get active agents count
    const activeCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM ai_agents WHERE user_id = ? AND status = ?'
    ).bind(user.id, 'active').first();
    
    return jsonResponse({
      total_agents: agents.results?.length || 0,
      total_conversations: chatCount?.count || 0,
      active_agents: activeCount?.count || 0,
      databases_count: dbCount?.count || 0,
      ai_workforce: agents.results || []
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    return jsonResponse({ error: 'Failed to load dashboard' }, 500);
  }
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

// Dashboard HTML Generator Function (Add to your Worker code)
function getDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Obeks AI - Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" />
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
    <style>
        :root {
            --primary-blue: #1f52dc;
            --secondary-blue: #38bdf8;
            --dark-bg: #0f172a;
            --card-bg: #1e293b;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--dark-bg);
            color: white;
            overflow-x: hidden;
        }
        
        /* Sidebar */
        .sidebar {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--secondary-blue) 100%);
            color: white;
            height: 100vh;
            position: fixed;
            left: 0;
            width: 280px;
            z-index: 1001;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
            overflow-y: auto;
        }
        
        .main-content {
            margin-left: 280px;
            padding: 20px;
            background: var(--dark-bg);
            min-height: 100vh;
        }
        
        /* Mobile responsiveness */
        @media (max-width: 992px) {
            .sidebar {
                left: -280px;
                transition: left 0.3s ease-in-out;
            }
            
            .sidebar.open {
                left: 0;
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .mobile-header {
                display: flex !important;
            }
        }
        
        /* Mobile Header */
        .mobile-header {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--secondary-blue) 100%);
            color: white;
            padding: 1rem;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            z-index: 1000;
            display: none;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        /* Cards */
        .ai-card {
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            border-radius: 1rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            background: var(--card-bg);
            color: white;
        }
        
        .ai-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 0.5rem 1rem rgba(0, 102, 255, 0.3);
        }
        
        .stats-card {
            background: var(--card-bg);
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            text-align: center;
            color: white;
            border: 1px solid rgba(56, 189, 248, 0.2);
        }
        
        .badge-online {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        
        .badge-offline {
            background: linear-gradient(135deg, #dc3545, #fd7e14);
        }
        
        /* Glass effect for cards */
        .glass-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(56, 189, 248, 0.2);
        }
        
        /* Input styling */
        .input-field {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: white;
        }
        
        .input-field:focus {
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--secondary-blue);
            color: white;
            box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25);
        }
        
        /* Button styling */
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--secondary-blue) 100%);
            border: none;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, var(--secondary-blue) 0%, var(--primary-blue) 100%);
            transform: translateY(-2px);
        }
        
        /* Watery tabs effect */
        .nav-tabs-watery .nav-link {
            background: transparent;
            border: none;
            color: rgba(255, 255, 255, 0.7);
            position: relative;
            overflow: hidden;
        }
        
        .nav-tabs-watery .nav-link.active {
            background: rgba(56, 189, 248, 0.1);
            color: white;
            border-bottom: 2px solid var(--secondary-blue);
        }
        
        .nav-tabs-watery .nav-link::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: -100%;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--secondary-blue), transparent);
            transition: left 0.3s;
        }
        
        .nav-tabs-watery .nav-link:hover::after {
            left: 100%;
        }
        
        /* Animation for cards */
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .float-animation {
            animation: float 5s ease-in-out infinite;
        }
        
        /* Loading spinner */
        .spinner-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            display: none;
        }
    </style>
</head>

<body>
    <!-- Loading Spinner -->
    <div class="spinner-overlay" id="loadingSpinner">
        <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;"></div>
    </div>
    
    <!-- Mobile Header -->
    <div class="mobile-header" id="mobileHeader">
        <button class="hamburger-btn" id="hamburgerBtn" type="button">
            <i class="bi bi-list"></i>
        </button>
        <h4 class="mb-0">Obeks AI</h4>
        <div style="width: 40px"></div>
    </div>
    
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-brand p-4">
            <h3 class="mb-0">Obeks AI</h3>
            <small class="text-white-50">AI Agent Management</small>
        </div>
        
        <nav class="sidebar-nav p-3">
            <a class="nav-link active mb-2" href="#" id="dashboardLink">
                <i class="bi bi-speedometer2 me-2"></i>Dashboard
            </a>
            <a class="nav-link mb-2" href="#" id="apiSettingsLink">
                <i class="bi bi-key me-2"></i>API Settings
            </a>
            <a class="nav-link mb-2" href="#" id="chatHistoryLink">
                <i class="bi bi-chat-dots me-2"></i>Chat History
            </a>
            <a class="nav-link mb-2" href="#" id="dataLink">
                <i class="bi bi-server me-2"></i>My Data
            </a>
            <a class="nav-link mb-2" href="#" id="apiDocsLink">
                <i class="bi bi-file-earmark-text me-2"></i>API Docs
            </a>
            
            <div class="mt-4 pt-3 border-top">
                <a class="nav-link text-warning" href="#" id="supportLink">
                    <i class="bi bi-question-circle me-2"></i>Support
                </a>
                <a class="nav-link text-danger" href="#" id="logoutLink">
                    <i class="bi bi-box-arrow-right me-2"></i>Logout
                </a>
            </div>
        </nav>
    </div>
    
    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1">Welcome to Obeks AI</h2>
                <span class="text-muted">Manage your AI agents in one place</span>
            </div>
            <div class="d-none d-md-block">
                <span class="badge bg-primary" id="activeAgentsBadge">Active Agents: 0</span>
            </div>
        </div>
        
        <!-- Quick Stats -->
        <div class="row mb-4" id="quickStats">
            <!-- Stats will be loaded via JavaScript -->
        </div>
        
        <!-- AI Workforce -->
        <div class="card glass-card mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Your AI Workforce</h5>
                <button class="btn btn-primary btn-sm" onclick="showAddAgentModal()">
                    <i class="bi bi-plus-circle"></i> Add Agent
                </button>
            </div>
            <div class="card-body">
                <div class="row" id="aiWorkforceContainer">
                    <!-- AI agents will be loaded here -->
                    <div class="text-center py-5">
                        <i class="bi bi-robot fs-1 text-muted mb-3"></i>
                        <p class="text-muted">No AI agents yet</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add Agent Modal -->
        <div class="modal fade" id="addAgentModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content bg-dark text-white">
                    <div class="modal-header">
                        <h5 class="modal-title">Add AI Agent</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row" id="availableAgentsGrid">
                            <!-- Available agents will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Telegram Setup Modal -->
        <div class="modal fade" id="telegramModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content bg-dark text-white">
                    <div class="modal-header">
                        <h5 class="modal-title">Setup Telegram Bot</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="telegramForm" onsubmit="return false;">
                            <input type="hidden" id="telegramAgentId">
                            <div class="mb-3">
                                <label class="form-label">Telegram Bot Token</label>
                                <input type="text" class="form-control input-field" id="telegramToken" 
                                       placeholder="Enter bot token from @BotFather" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Webhook URL</label>
                                <input type="text" class="form-control input-field" id="webhookUrl" readonly>
                            </div>
                            <button type="button" class="btn btn-primary w-100" onclick="setupTelegramBot()">
                                Setup Webhook
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Dashboard JavaScript -->
    <script>
        // Global variables
        let currentUser = null;
        let agents = [];
        
        // DOM Ready - FIXED: No auto-reload
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Dashboard initialized');
            
            // Check authentication
            checkAuth();
            
            // Initialize sidebar
            initSidebar();
            
            // Load dashboard data
            loadDashboardData();
            
            // Load available agents for modal
            loadAvailableAgents();
        });
        
        // Check authentication
        async function checkAuth() {
            const token = localStorage.getItem('token');
            if (!token) {
                window.location.href = '/login';
                return;
            }
            
            try {
                currentUser = JSON.parse(localStorage.getItem('user'));
                console.log('User authenticated:', currentUser?.username);
            } catch (e) {
                localStorage.clear();
                window.location.href = '/login';
            }
        }
        
        // Initialize sidebar - FIXED: Prevent default behavior
        function initSidebar() {
            const hamburgerBtn = document.getElementById('hamburgerBtn');
            const sidebar = document.getElementById('sidebar');
            
            if (hamburgerBtn && sidebar) {
                hamburgerBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    sidebar.classList.toggle('open');
                });
            }
            
            // Navigation links - FIXED: Prevent page reload
            const navLinks = ['dashboardLink', 'apiSettingsLink', 'chatHistoryLink', 
                            'dataLink', 'apiDocsLink', 'supportLink', 'logoutLink'];
            
            navLinks.forEach(linkId => {
                const link = document.getElementById(linkId);
                if (link) {
                    link.addEventListener('click', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        
                        switch(linkId) {
                            case 'dashboardLink':
                                loadDashboardData();
                                break;
                            case 'apiSettingsLink':
                                loadAPISettings();
                                break;
                            case 'chatHistoryLink':
                                loadChatHistory();
                                break;
                            case 'dataLink':
                                loadMyData();
                                break;
                            case 'apiDocsLink':
                                loadAPIDocs();
                                break;
                            case 'supportLink':
                                showSupport();
                                break;
                            case 'logoutLink':
                                logout();
                                break;
                        }
                    });
                }
            });
            
            // Close sidebar when clicking outside on mobile
            document.addEventListener('click', function(e) {
                if (window.innerWidth < 992) {
                    const sidebar = document.getElementById('sidebar');
                    const hamburgerBtn = document.getElementById('hamburgerBtn');
                    
                    if (sidebar && hamburgerBtn && 
                        !sidebar.contains(e.target) && 
                        !hamburgerBtn.contains(e.target)) {
                        sidebar.classList.remove('open');
                    }
                }
            });
        }
        
        // Show loading spinner
        function showLoading() {
            document.getElementById('loadingSpinner').style.display = 'flex';
        }
        
        // Hide loading spinner
        function hideLoading() {
            document.getElementById('loadingSpinner').style.display = 'none';
        }
        
        // Load dashboard data - FIXED: No page reload
        async function loadDashboardData() {
            showLoading();
            try {
                const token = localStorage.getItem('token');
                const response = await fetch('/api/dashboard', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.status === 401) {
                    logout();
                    return;
                }
                
                if (response.ok) {
                    const data = await response.json();
                    updateDashboard(data);
                    agents = data.ai_workforce || [];
                } else {
                    console.error('Failed to load dashboard');
                }
            } catch (error) {
                console.error('Error:', error);
            } finally {
                hideLoading();
            }
        }
        
        // Update dashboard UI
        function updateDashboard(data) {
            // Update quick stats
            const statsHtml = \`
                <div class="col-6 col-md-3 mb-3">
                    <div class="stats-card float-animation">
                        <i class="bi bi-robot fs-1 text-primary mb-2"></i>
                        <h3>\${data.total_agents || 0}</h3>
                        <p class="text-muted mb-0">Total Agents</p>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="stats-card float-animation">
                        <i class="bi bi-chat-dots fs-1 text-success mb-2"></i>
                        <h3>\${data.total_conversations || 0}</h3>
                        <p class="text-muted mb-0">Conversations</p>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="stats-card float-animation">
                        <i class="bi bi-activity fs-1 text-warning mb-2"></i>
                        <h3>\${data.active_agents || 0}</h3>
                        <p class="text-muted mb-0">Active Now</p>
                    </div>
                </div>
                <div class="col-6 col-md-3 mb-3">
                    <div class="stats-card float-animation">
                        <i class="bi bi-server fs-1 text-info mb-2"></i>
                        <h3>\${data.databases_count || 0}</h3>
                        <p class="text-muted mb-0">Data Loaded</p>
                    </div>
                </div>
            \`;
            
            document.getElementById('quickStats').innerHTML = statsHtml;
            document.getElementById('activeAgentsBadge').textContent = \`Active Agents: \${data.active_agents || 0}\`;
            
            // Update AI workforce
            renderAIWorkforce(data.ai_workforce || []);
        }
        
        // Render AI workforce
        function renderAIWorkforce(agents) {
            const container = document.getElementById('aiWorkforceContainer');
            
            if (!agents || agents.length === 0) {
                container.innerHTML = \`
                    <div class="text-center py-5">
                        <i class="bi bi-robot fs-1 text-muted mb-3"></i>
                        <p class="text-muted">No AI agents yet</p>
                        <button class="btn btn-primary" onclick="showAddAgentModal()">
                            Add Your First AI
                        </button>
                    </div>
                \`;
                return;
            }
            
            const html = agents.map(agent => \`
                <div class="col-12 col-md-6 col-lg-4 mb-3">
                    <div class="card ai-card h-100">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h5 class="card-title">\${agent.name || 'Unnamed'}</h5>
                                <span class="badge \${agent.status === 'active' ? 'badge-online' : 'badge-offline'}">
                                    \${agent.status || 'inactive'}
                                </span>
                            </div>
                            <h6 class="card-subtitle mb-2 text-muted">
                                <i class="bi bi-\${getAgentIcon(agent.agent_type)} me-1"></i>
                                \${formatAgentType(agent.agent_type)}
                            </h6>
                            <p class="card-text small">Created: \${formatDate(agent.created_at)}</p>
                            
                            \${renderAgentActions(agent)}
                        </div>
                    </div>
                </div>
            \`).join('');
            
            container.innerHTML = html;
            container.classList.remove('text-center', 'py-5');
            container.classList.add('row');
        }
        
        // Get agent icon
        function getAgentIcon(type) {
            const icons = {
                'telegram_bot': 'telegram',
                'whatsapp': 'whatsapp',
                'website': 'globe',
                'security': 'shield-check',
                'ecommerce': 'cart',
                'facebook': 'facebook',
                'instagram': 'instagram'
            };
            return icons[type] || 'robot';
        }
        
        // Format agent type
        function formatAgentType(type) {
            return type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
        }
        
        // Format date
        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            return new Date(dateString).toLocaleDateString();
        }
        
        // Render agent actions
        function renderAgentActions(agent) {
            if (agent.agent_type === 'telegram_bot') {
                return \`
                    <div class="mt-3">
                        <button class="btn btn-outline-primary btn-sm w-100" 
                                onclick="setupTelegramAgent('\${agent.id}')">
                            \${agent.telegram_bot_token ? 'Reconfigure' : 'Setup'} Telegram
                        </button>
                        \${agent.telegram_bot_token ? \`
                            <small class="text-success d-block mt-1">
                                <i class="bi bi-check-circle"></i> Configured
                            </small>
                        \` : ''}
                    </div>
                \`;
            }
            
            return \`
                <div class="mt-3">
                    <button class="btn btn-outline-secondary btn-sm w-100" disabled>
                        Coming Soon
                    </button>
                </div>
            \`;
        }
        
        // Load available agents
        async function loadAvailableAgents() {
            const availableAgents = [
                { id: 'telegram_bot', name: 'Telegram Bot', description: 'Customer support bot for Telegram', icon: 'telegram' },
                { id: 'whatsapp', name: 'WhatsApp Bot', description: 'Business messaging on WhatsApp', icon: 'whatsapp' },
                { id: 'website', name: 'Website AI', description: 'Add AI to your website', icon: 'globe' },
                { id: 'security', name: 'Security AI', description: 'Cyber security analysis', icon: 'shield-check' },
                { id: 'ecommerce', name: 'E-Commerce', description: 'AI-powered online stores', icon: 'cart' },
                { id: 'facebook', name: 'Facebook', description: 'Social media management', icon: 'facebook' },
                { id: 'instagram', name: 'Instagram', description: 'Instagram content', icon: 'instagram' }
            ];
            
            const container = document.getElementById('availableAgentsGrid');
            container.innerHTML = availableAgents.map(agent => \`
                <div class="col-6 mb-3">
                    <div class="card ai-card h-100 text-center" 
                         onclick="addAgent('\${agent.id}', '\${agent.name}')"
                         style="cursor: pointer;">
                        <div class="card-body">
                            <div class="mb-3" style="font-size: 2.5rem">
                                <i class="bi bi-\${agent.icon} text-primary"></i>
                            </div>
                            <h6 class="card-title">\${agent.name}</h6>
                            <p class="card-text small text-muted">\${agent.description}</p>
                        </div>
                    </div>
                </div>
            \`).join('');
        }
        
        // Show add agent modal
        function showAddAgentModal() {
            const modal = new bootstrap.Modal(document.getElementById('addAgentModal'));
            modal.show();
        }
        
        // Add agent - FIXED: Prevent form submission
        async function addAgent(agentType, agentName) {
            const name = prompt(\`Enter a name for your \${agentName}:\`, \`My \${agentName}\`);
            if (!name) return;
            
            showLoading();
            try {
                const token = localStorage.getItem('token');
                const response = await fetch('/api/agents/create', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        ai_type: agentType,
                        name: name,
                        description: \`AI Agent for \${agentName}\`
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Close modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addAgentModal'));
                    modal.hide();
                    
                    // Show success
                    showNotification('Agent added successfully!', 'success');
                    
                    // Reload dashboard
                    loadDashboardData();
                } else {
                    showNotification(data.error || 'Failed to add agent', 'error');
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('Network error', 'error');
            } finally {
                hideLoading();
            }
        }
        
        // Setup Telegram agent
        function setupTelegramAgent(agentId) {
            document.getElementById('telegramAgentId').value = agentId;
            document.getElementById('webhookUrl').value = \`\${window.location.origin}/api/webhook/telegram/\${agentId}\`;
            
            const modal = new bootstrap.Modal(document.getElementById('telegramModal'));
            modal.show();
        }
        
        // Setup Telegram bot
        async function setupTelegramBot() {
            const agentId = document.getElementById('telegramAgentId').value;
            const token = document.getElementById('telegramToken').value;
            
            if (!token) {
                showNotification('Please enter Telegram bot token', 'warning');
                return;
            }
            
            showLoading();
            try {
                const userToken = localStorage.getItem('token');
                const response = await fetch('/api/agents/telegram/setup', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + userToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        agent_id: agentId,
                        telegram_token: token
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Close modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('telegramModal'));
                    modal.hide();
                    
                    showNotification('Telegram bot configured successfully!', 'success');
                    loadDashboardData();
                } else {
                    showNotification(data.error || 'Failed to setup bot', 'error');
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('Network error', 'error');
            } finally {
                hideLoading();
            }
        }
        
        // Other page loaders
        async function loadAPISettings() {
            showNotification('API Settings page coming soon!', 'info');
        }
        
        async function loadChatHistory() {
            showNotification('Chat History page coming soon!', 'info');
        }
        
        async function loadMyData() {
            showNotification('My Data page coming soon!', 'info');
        }
        
        async function loadAPIDocs() {
            showNotification('API Documentation page coming soon!', 'info');
        }
        
        function showSupport() {
            alert('Support: Contact us at support@obeks.ai');
        }
        
        // Logout
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                localStorage.clear();
                window.location.href = '/login';
            }
        }
        
        // Show notification
        function showNotification(message, type = 'info') {
            // Remove existing notifications
            const existing = document.querySelector('.custom-notification');
            if (existing) existing.remove();
            
            const alertClass = {
                'success': 'alert-success',
                'error': 'alert-danger',
                'warning': 'alert-warning',
                'info': 'alert-info'
            }[type] || 'alert-info';
            
            const notification = \`
                <div class="alert \${alertClass} alert-dismissible fade show custom-notification"
                     style="position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;">
                    \${message}
                    <button type="button" class="btn-close" onclick="this.parentElement.remove()"></button>
                </div>
            \`;
            
            document.body.insertAdjacentHTML('beforeend', notification);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                const notif = document.querySelector('.custom-notification');
                if (notif) notif.remove();
            }, 5000);
        }
        
        // Prevent accidental refresh
        window.addEventListener('beforeunload', function(e) {
            if (document.getElementById('loadingSpinner').style.display === 'flex') {
                e.preventDefault();
                e.returnValue = '';
            }
        });
    </script>
</body>
</html>`;
}

function getLoginHTML() {
  return `<!DOCTYPE html>
<html>
<head>
    <title>Obeks AI - Login</title>
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #1f52dc 0%, #38bdf8 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #1f52dc 0%, #38bdf8 100%);
            border: none;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2 class="text-center mb-4">Welcome to Obeks AI</h2>
        <form id="loginForm">
            <div class="mb-3">
                <input type="email" class="form-control" id="email" placeholder="Email" required>
            </div>
            <div class="mb-3">
                <input type="password" class="form-control" id="password" placeholder="Password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <div class="text-center mt-3">
            <a href="#" id="showRegister">Create Account</a>
        </div>
        
        <form id="registerForm" style="display: none;">
            <div class="mb-3">
                <input type="text" class="form-control" id="regUsername" placeholder="Username" required>
            </div>
            <div class="mb-3">
                <input type="email" class="form-control" id="regEmail" placeholder="Email" required>
            </div>
            <div class="mb-3">
                <input type="password" class="form-control" id="regPassword" placeholder="Password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Register</button>
        </form>
    </div>
    
    <script>
        document.getElementById('showRegister').addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
        });
        
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                window.location.href = '/dashboard';
            } else {
                alert(data.error || 'Login failed');
            }
        });
        
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('regUsername').value;
            const email = document.getElementById('regEmail').value;
            const password = document.getElementById('regPassword').value;
            
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                window.location.href = '/dashboard';
            } else {
                alert(data.error || 'Registration failed');
            }
        });
    </script>
</body>
</html>`;
}

