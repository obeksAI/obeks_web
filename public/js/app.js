class ObeksAI {
  constructor() {
    this.apiBase = '/api';
    this.token = localStorage.getItem('token');
    this.user = JSON.parse(localStorage.getItem('user') || 'null');
    this.init();
  }
  
  async init() {
    this.setupEventListeners();
    this.checkAuth();
    await this.loadDashboard();
  }
  
  checkAuth() {
    const publicPages = ['/login', '/register'];
    const currentPath = window.location.pathname;
    
    if (!this.token && !publicPages.includes(currentPath)) {
      this.redirectToLogin();
    } else if (this.token && publicPages.includes(currentPath)) {
      window.location.href = '/';
    }
  }
  
  redirectToLogin() {
    window.location.href = '/login';
  }
  
  async login(email, password) {
    try {
      const response = await fetch(`${this.apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        this.token = data.token;
        this.user = data.user;
        localStorage.setItem('token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        window.location.href = '/';
      } else {
        throw new Error(data.error || 'Login failed');
      }
    } catch (error) {
      this.showNotification(error.message, 'error');
    }
  }
  
  async register(email, username, password) {
    try {
      const response = await fetch(`${this.apiBase}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, username, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        this.token = data.token;
        this.user = data.user;
        localStorage.setItem('token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        window.location.href = '/';
      } else {
        throw new Error(data.error || 'Registration failed');
      }
    } catch (error) {
      this.showNotification(error.message, 'error');
    }
  }
  
  async loadDashboard() {
    if (!this.token) return;
    
    try {
      // Load user agents
      const agentsResponse = await this.makeRequest('/agents');
      this.renderAgents(agentsResponse.agents || []);
      
      // Load API keys
      const keysResponse = await this.makeRequest('/api-keys');
      this.renderAPIKeys(keysResponse.keys || []);
      
      // Load chat history
      const historyResponse = await this.makeRequest('/chat/history');
      this.renderChatHistory(historyResponse.history || []);
      
      // Load vector databases
      const vectorDBsResponse = await this.makeRequest('/vector-dbs');
      this.renderVectorDBs(vectorDBsResponse.databases || []);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
    }
  }
  
  async createTelegramAgent(name, instructions, telegramToken) {
    try {
      const response = await this.makeRequest('/agents/telegram', 'POST', {
        name,
        instructions,
        telegram_token: telegramToken
      });
      
      this.showNotification('Telegram bot created successfully!', 'success');
      await this.loadDashboard();
      return response;
    } catch (error) {
      this.showNotification(error.message, 'error');
      throw error;
    }
  }
  
  async addAPIKey(platform, apiKey) {
    try {
      await this.makeRequest('/api-keys', 'POST', {
        platform,
        api_key: apiKey
      });
      
      this.showNotification('API key added successfully!', 'success');
      await this.loadDashboard();
    } catch (error) {
      this.showNotification(error.message, 'error');
    }
  }
  
  async createPlatformAPIKey(keyName, permissions) {
    try {
      const response = await this.makeRequest('/platform/keys', 'POST', {
        key_name: keyName,
        permissions: permissions || ['read', 'chat', 'agent_management']
      });
      
      this.showNotification('Platform API key created!', 'success');
      return response.apiKey;
    } catch (error) {
      this.showNotification(error.message, 'error');
    }
  }
  
  async createVectorDB(name, description, provider) {
    try {
      await this.makeRequest('/vector-dbs', 'POST', {
        name,
        description,
        embeddings_provider: provider
      });
      
      this.showNotification('Vector database created!', 'success');
      await this.loadDashboard();
    } catch (error) {
      this.showNotification(error.message, 'error');
    }
  }
  
  async makeRequest(endpoint, method = 'GET', data = null) {
    const options = {
      method,
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(data);
    }
    
    const response = await fetch(`${this.apiBase}${endpoint}`, options);
    const result = await response.json();
    
    if (!response.ok) {
      throw new Error(result.error || 'Request failed');
    }
    
    return result;
  }
  
  renderAgents(agents) {
    const container = document.getElementById('agents-container');
    if (!container) return;
    
    container.innerHTML = agents.map(agent => `
      <div class="glass-card agent-card float-animation">
        <div class="agent-status status-${agent.status}">
          ${agent.status}
        </div>
        <h3>${agent.name}</h3>
        <p>Type: ${agent.agent_type}</p>
        <p>Created: ${new Date(agent.created_at).toLocaleDateString()}</p>
        <button onclick="obeksAI.viewAgent('${agent.id}')" class="btn btn-secondary mt-3">
          View Details
        </button>
      </div>
    `).join('');
  }
  
  renderAPIKeys(keys) {
    const container = document.getElementById('api-keys-container');
    if (!container) return;
    
    container.innerHTML = keys.map(key => `
      <div class="glass-card">
        <div class="flex justify-between items-center">
          <div>
            <h4>${key.platform}</h4>
            <p class="text-sm opacity-75">Added: ${new Date(key.created_at).toLocaleDateString()}</p>
          </div>
          <button onclick="obeksAI.deleteAPIKey('${key.id}')" class="btn btn-danger">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
    `).join('');
  }
  
  renderChatHistory(history) {
    const container = document.getElementById('chat-history-container');
    if (!container) return;
    
    container.innerHTML = history.map(msg => `
      <div class="message ${msg.user_message ? 'message-user' : 'message-ai'}">
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold">${msg.agent_name || 'Agent'}</span>
          <span class="text-xs opacity-75">${new Date(msg.timestamp).toLocaleString()}</span>
        </div>
        <p>${msg.user_message || msg.ai_response}</p>
      </div>
    `).join('');
  }
  
  renderVectorDBs(databases) {
    const container = document.getElementById('vector-dbs-container');
    if (!container) return;
    
    container.innerHTML = databases.map(db => `
      <div class="glass-card">
        <h4>${db.name}</h4>
        <p class="text-sm opacity-75 mb-2">${db.description || 'No description'}</p>
        <div class="flex justify-between items-center">
          <span class="status-${db.status}">${db.status}</span>
          <button onclick="obeksAI.manageVectorDB('${db.id}')" class="btn btn-secondary btn-sm">
            Manage
          </button>
        </div>
      </div>
    `).join('');
  }
  
  showNotification(message, type = 'info') {
    // Create and show notification
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 24px;
      border-radius: 12px;
      color: white;
      z-index: 1000;
      animation: slideIn 0.3s ease;
    `;
    
    if (type === 'success') {
      notification.style.background = 'var(--success)';
    } else if (type === 'error') {
      notification.style.background = 'var(--danger)';
    } else {
      notification.style.background = 'var(--primary-blue)';
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
  
  setupEventListeners() {
    // Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        await this.login(email, password);
      });
    }
    
    // Register form
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
      registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('reg-email').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('reg-password').value;
        await this.register(email, username, password);
      });
    }
    
    // Create agent form
    const agentForm = document.getElementById('create-agent-form');
    if (agentForm) {
      agentForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('agent-name').value;
        const instructions = document.getElementById('agent-instructions').value;
        const telegramToken = document.getElementById('telegram-token').value;
        await this.createTelegramAgent(name, instructions, telegramToken);
      });
    }
    
    // Add API key form
    const apiKeyForm = document.getElementById('add-api-key-form');
    if (apiKeyForm) {
      apiKeyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const platform = document.getElementById('platform').value;
        const apiKey = document.getElementById('api-key-value').value;
        await this.addAPIKey(platform, apiKey);
      });
    }
    
    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        localStorage.clear();
        this.redirectToLogin();
      });
    }
  }
}

// Initialize the app
const obeksAI = new ObeksAI();

// Make available globally
window.obeksAI = obeksAI;
