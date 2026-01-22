-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    api_key TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User API keys table
CREATE TABLE IF NOT EXISTS user_api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    api_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- AI Agents table
CREATE TABLE IF NOT EXISTS ai_agents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    agent_type TEXT NOT NULL DEFAULT 'telegram_bot',
    configuration JSON NOT NULL,
    status TEXT NOT NULL DEFAULT 'inactive',
    telegram_bot_token TEXT,
    instructions TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Agent Chat History
CREATE TABLE IF NOT EXISTS agent_chat_history (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    user_message TEXT,
    ai_response TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata JSON,
    FOREIGN KEY (agent_id) REFERENCES ai_agents(id) ON DELETE CASCADE
);

-- Vector Databases
CREATE TABLE IF NOT EXISTS vector_databases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    embeddings_provider TEXT NOT NULL DEFAULT 'openai',
    status TEXT NOT NULL DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Vector Documents
CREATE TABLE IF NOT EXISTS vector_documents (
    id TEXT PRIMARY KEY,
    vector_db_id TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata JSON,
    embedding BLOB,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vector_db_id) REFERENCES vector_databases(id) ON DELETE CASCADE
);

-- Platform API Keys (for users to integrate with our platform)
CREATE TABLE IF NOT EXISTS platform_api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    permissions JSON NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_ai_agents_user_id ON ai_agents(user_id);
CREATE INDEX idx_agent_chat_history_agent_id ON agent_chat_history(agent_id);
CREATE INDEX idx_user_api_keys_user_id ON user_api_keys(user_id);
