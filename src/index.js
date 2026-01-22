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
function getDashboardHTML(userData = {}) {
  // Default data if none provided
  const data = {
    user_ai: userData.user_ai || [],
    active_ai_count: userData.active_ai_count || 0,
    user_chat_count: userData.user_chat_count || 0,
    user_db_count: userData.user_db_count || 0,
    available_ai: userData.available_ai || [
      { id: 'telegram', name: 'Telegram Bot', description: 'Customer support bot for Telegram' },
      { id: 'whatsapp', name: 'WhatsApp Bot', description: 'Business messaging on WhatsApp' },
      { id: 'website', name: 'Website AI', description: 'Add AI to your website' },
      { id: 'security', name: 'Cyber Security', description: 'Security analysis and monitoring' },
      { id: 'ecommerce', name: 'E-Commerce', description: 'AI-powered online stores' },
      { id: 'facebook', name: 'Facebook', description: 'Social media management' },
      { id: 'instagram', name: 'Instagram', description: 'Instagram content and engagement' }
    ],
    request: { host_url: 'https://your-worker.workers.dev/' }
  };

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
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f8f9fa;
            overflow-x: hidden;
        }
        
        /* Sidebar styling */
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
        }
        
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
        
        /* Add your existing CSS styles here */
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
        }
        
        .ai-card {
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            border-radius: 1rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }
        
        .ai-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        
        .stats-card {
            background: white;
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            text-align: center;
        }
        
        .badge-online {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        
        .badge-offline {
            background: linear-gradient(135deg, #dc3545, #fd7e14);
        }
    </style>
</head>

<body>
    <!-- Mobile Header -->
    <div class="mobile-header" id="mobileHeader">
        <button class="hamburger-btn" id="hamburgerBtn">
            <i class="bi bi-list"></i>
        </button>
        <h4 class="mb-0">Obeks AI</h4>
        <div style="width: 40px"></div>
    </div>
    
    <!-- Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    
    <!-- Sidebar Navigation -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-brand">
            <h4 class="mb-0">Obeks AI</h4>
            <small class="text-white-50">AI Agent Management</small>
        </div>
        
        <nav class="sidebar-nav">
            <a class="nav-link active" href="#" id="dashboardLink">
                <i class="bi bi-speedometer2"></i>Dashboard
            </a>
            <a class="nav-link" href="#" id="apiSettingsLink">
                <i class="bi bi-key"></i>API Settings
            </a>
            <a class="nav-link" href="#" id="chatHistoryLink">
                <i class="bi bi-chat-dots"></i>Chat History
            </a>
            <a class="nav-link" href="#" id="dataLink">
                <i class="bi bi-server"></i>My Data
            </a>
            <a class="nav-link" href="#" id="apiDocsLink">
                <i class="bi bi-file-earmark-text"></i>API Documentation
            </a>
            
            <!-- Logout Button -->
            <a class="nav-link" href="#" id="logoutLink">
                <i class="bi bi-box-arrow-right"></i>Logout
            </a>
        </nav>
    </div>
    
    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <!-- Header Content -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1">Welcome to Obeks AI</h2>
                <span class="text-muted">Manage your AI agents in one place</span>
            </div>
            <div class="d-none d-md-block">
                <span class="badge bg-primary" id="activeAgentsBadge">Active Agents: ${data.active_ai_count}</span>
            </div>
        </div>
        
        <!-- Quick Stats -->
        <div class="row mb-4" id="quickStats">
            <div class="col-6 col-md-3 mb-3">
                <div class="stats-card">
                    <i class="bi bi-robot fs-1 text-primary mb-2"></i>
                    <h3 id="totalAgents">${data.user_ai.length}</h3>
                    <p class="text-muted mb-0">Total Agents</p>
                </div>
            </div>
            <div class="col-6 col-md-3 mb-3">
                <div class="stats-card">
                    <i class="bi bi-chat-dots fs-1 text-success mb-2"></i>
                    <h3 id="totalConversations">${data.user_chat_count}</h3>
                    <p class="text-muted mb-0">Conversations</p>
                </div>
            </div>
            <div class="col-6 col-md-3 mb-3">
                <div class="stats-card">
                    <i class="bi bi-activity fs-1 text-warning mb-2"></i>
                    <h3 id="activeAgents">${data.active_ai_count}</h3>
                    <p class="text-muted mb-0">Active Now</p>
                </div>
            </div>
            <div class="col-6 col-md-3 mb-3">
                <div class="stats-card">
                    <i class="bi bi-server fs-1 text-info mb-2"></i>
                    <h3 id="databasesCount">${data.user_db_count}</h3>
                    <p class="text-muted mb-0">Data Loaded</p>
                </div>
            </div>
        </div>
        
        <!-- Your AI Workforce Section -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">Your AI Workforce</h5>
                        <span class="badge bg-primary">${data.user_ai.length} Agents</span>
                    </div>
                    <div class="card-body" id="aiWorkforceContainer">
                        ${renderAIWorkforce(data.user_ai)}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add AI Section -->
        <div class="row" id="add-ai-section">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-white">
                        <h5 class="card-title mb-0">Add AI Agent</h5>
                    </div>
                    <div class="card-body">
                        <div class="row" id="availableAIContainer">
                            ${renderAvailableAI(data.available_ai)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Dashboard JavaScript -->
    <script>
        // DOM Ready
        document.addEventListener('DOMContentLoaded', function() {
            // Sidebar functionality
            const hamburgerBtn = document.getElementById('hamburgerBtn');
            const sidebar = document.getElementById('sidebar');
            const sidebarOverlay = document.getElementById('sidebarOverlay');
            
            if (hamburgerBtn) {
                hamburgerBtn.addEventListener('click', function() {
                    sidebar.classList.toggle('open');
                    sidebarOverlay.classList.toggle('active');
                });
            }
            
            if (sidebarOverlay) {
                sidebarOverlay.addEventListener('click', function() {
                    sidebar.classList.remove('open');
                    sidebarOverlay.classList.remove('active');
                });
            }
            
            // Navigation Links
            document.getElementById('dashboardLink').addEventListener('click', function(e) {
                e.preventDefault();
                loadDashboard();
            });
            
            document.getElementById('apiSettingsLink').addEventListener('click', function(e) {
                e.preventDefault();
                loadAPISettings();
            });
            
            document.getElementById('chatHistoryLink').addEventListener('click', function(e) {
                e.preventDefault();
                loadChatHistory();
            });
            
            document.getElementById('dataLink').addEventListener('click', function(e) {
                e.preventDefault();
                loadMyData();
            });
            
            document.getElementById('apiDocsLink').addEventListener('click', function(e) {
                e.preventDefault();
                loadAPIDocs();
            });
            
            document.getElementById('logoutLink').addEventListener('click', function(e) {
                e.preventDefault();
                logout();
            });
            
            // Initialize
            loadDashboardData();
        });
        
        // API Functions
        async function loadDashboardData() {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    window.location.href = '/';
                    return;
                }
                
                const response = await fetch('/api/dashboard', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    updateDashboard(data);
                } else {
                    console.error('Failed to load dashboard data');
                }
            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }
        
        function updateDashboard(data) {
            document.getElementById('totalAgents').textContent = data.total_agents || 0;
            document.getElementById('totalConversations').textContent = data.total_conversations || 0;
            document.getElementById('activeAgents').textContent = data.active_agents || 0;
            document.getElementById('databasesCount').textContent = data.databases_count || 0;
            document.getElementById('activeAgentsBadge').textContent = 'Active Agents: ' + (data.active_agents || 0);
            
            if (data.ai_workforce) {
                document.getElementById('aiWorkforceContainer').innerHTML = renderAIWorkforce(data.ai_workforce);
            }
        }
        
        async function loadAPISettings() {
            // Load API settings page
            const mainContent = document.getElementById('mainContent');
            mainContent.innerHTML = '<h2>API Settings - Coming Soon</h2>';
        }
        
        async function loadChatHistory() {
            // Load chat history
            const mainContent = document.getElementById('mainContent');
            mainContent.innerHTML = '<h2>Chat History - Coming Soon</h2>';
        }
        
        async function loadMyData() {
            // Load My Data page
            const mainContent = document.getElementById('mainContent');
            mainContent.innerHTML = '<h2>My Data - Coming Soon</h2>';
        }
        
        async function loadAPIDocs() {
            // Load API Documentation
            const mainContent = document.getElementById('mainContent');
            mainContent.innerHTML = '<h2>API Documentation - Coming Soon</h2>';
        }
        
        function loadDashboard() {
            window.location.reload();
        }
        
        async function logout() {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/';
        }
        
        // Render functions
        function renderAIWorkforce(agents) {
            if (!agents || agents.length === 0) {
                return \`
                    <div class="text-center py-5">
                        <i class="bi bi-robot fs-1 text-muted mb-3"></i>
                        <p class="text-muted">You haven't added any AI workforce yet.</p>
                        <a href="#add-ai-section" class="btn btn-primary">Add Your First AI</a>
                    </div>
                \`;
            }
            
            return agents.map(agent => \`
                <div class="col-12 col-md-6 col-lg-4 mb-3">
                    <div class="card ai-card h-100">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h5 class="card-title">\${agent.name || 'Unnamed Agent'}</h5>
                                <span class="badge \${agent.status === 'active' ? 'badge-online' : 'badge-offline'}">
                                    \${agent.status || 'inactive'}
                                </span>
                            </div>
                            <h6 class="card-subtitle mb-2 text-muted">
                                <i class="bi bi-\${agent.type || 'robot'} me-1"></i>
                                \${agent.type || 'AI Agent'}
                            </h6>
                            <p class="card-text small">\${agent.description || 'No description available'}</p>
                            
                            <!-- Agent-specific configurations -->
                            \${renderAgentConfig(agent)}
                            
                            <div class="d-flex justify-content-between align-items-center mt-3 pt-2 border-top">
                                <small class="text-muted">\${agent.created_at ? agent.created_at.substring(0, 10) : 'N/A'}</small>
                                <a href="#" class="text-danger" onclick="deleteAgent('\${agent.id}')">
                                    <i class="bi bi-trash"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            \`).join('');
        }
        
        function renderAgentConfig(agent) {
            if (agent.type === 'telegram') {
                return \`
                    <div class="mb-2">
                        <small class="text-muted d-block mb-1">Webhook URL:</small>
                        <input type="text" class="form-control form-control-sm" 
                               value="\${window.location.origin}/api/webhook/telegram/\${agent.id}" 
                               readonly onclick="this.select()">
                    </div>
                    <form onsubmit="setupTelegramAgent(event, '\${agent.id}')">
                        <div class="input-group input-group-sm mb-2">
                            <input type="text" class="form-control" 
                                   placeholder="Telegram Bot Token" 
                                   id="token-\${agent.id}" required>
                            <button class="btn btn-outline-primary" type="submit">Set Webhook</button>
                        </div>
                    </form>
                \`;
            }
            // Add other agent types here
            return '';
        }
        
        function renderAvailableAI(availableAI) {
            return availableAI.map(ai => \`
                <div class="col-12 col-sm-6 col-md-4 col-lg-3 mb-3">
                    <div class="card ai-card h-100 text-center">
                        <div class="card-body">
                            <div class="mb-3" style="font-size: 2.5rem">
                                <i class="bi bi-\${ai.id} text-primary"></i>
                            </div>
                            <h5 class="card-title">\${ai.name}</h5>
                            <p class="card-text small text-muted">\${ai.description}</p>
                            <button class="btn btn-primary btn-sm" onclick="addAgent('\${ai.id}')">
                                Add Agent
                            </button>
                        </div>
                    </div>
                </div>
            \`).join('');
        }
        
        // Agent Actions
        async function addAgent(aiId) {
            try {
                const token = localStorage.getItem('token');
                const name = prompt('Enter a name for your AI agent:');
                if (!name) return;
                
                const response = await fetch('/api/agents/create', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        ai_type: aiId,
                        name: name,
                        description: 'AI Agent for ' + aiId
                    })
                });
                
                if (response.ok) {
                    alert('Agent added successfully!');
                    loadDashboardData();
                } else {
                    const error = await response.json();
                    alert('Error: ' + (error.error || 'Failed to add agent'));
                }
            } catch (error) {
                console.error('Error adding agent:', error);
                alert('Network error. Please try again.');
            }
        }
        
        async function setupTelegramAgent(event, agentId) {
            event.preventDefault();
            const token = document.getElementById('token-' + agentId).value;
            
            if (!token) {
                alert('Please enter a Telegram Bot Token');
                return;
            }
            
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
                
                if (response.ok) {
                    alert('Telegram bot configured successfully!');
                } else {
                    const error = await response.json();
                    alert('Error: ' + (error.error || 'Failed to setup bot'));
                }
            } catch (error) {
                console.error('Error setting up Telegram:', error);
                alert('Network error. Please try again.');
            }
        }
        
        async function deleteAgent(agentId) {
            if (!confirm('Are you sure you want to delete this AI agent?')) {
                return;
            }
            
            try {
                const token = localStorage.getItem('token');
                const response = await fetch('/api/agents/' + agentId, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                
                if (response.ok) {
                    alert('Agent deleted successfully!');
                    loadDashboardData();
                } else {
                    const error = await response.json();
                    alert('Error: ' + (error.error || 'Failed to delete agent'));
                }
            } catch (error) {
                console.error('Error deleting agent:', error);
                alert('Network error. Please try again.');
            }
        }
    </script>
</body>
</html>`;
}

// Helper function to render AI workforce
function renderAIWorkforce(agents) {
  if (!agents || agents.length === 0) {
    return '<p>No AI agents yet</p>';
  }
  // Return HTML string
  return agents.map(agent => `
    <div class="col-12 col-md-6 col-lg-4 mb-3">
      <div class="card ai-card">
        <div class="card-body">
          <h5>${agent.name}</h5>
          <p>${agent.description || 'No description'}</p>
        </div>
      </div>
    </div>
  `).join('');
}

// Helper function to render available AI
function renderAvailableAI(availableAI) {
  return availableAI.map(ai => `
    <div class="col-12 col-sm-6 col-md-4 col-lg-3 mb-3">
      <div class="card ai-card">
        <div class="card-body">
          <h5>${ai.name}</h5>
          <p>${ai.description}</p>
        </div>
      </div>
    </div>
  `).join('');
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

