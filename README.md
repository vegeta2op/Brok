# Brok - Autonomous Pentesting Agent

**An AI agent that actually THINKS like a penetration tester** - not just another vulnerability scanner.

Brok uses advanced AI (GPT-5, Claude, Gemini) to intelligently analyze, reason about, and test web applications. Watch it think in real-time as it discovers vulnerabilities through creative problem-solving and adaptive strategies.

```
🤖 AI: "I detected PHP + MySQL. Let me craft targeted SQLi payloads..."
🤖 AI: "Found admin panel at /admin. Testing authentication bypass..."
🤖 AI: "XSS payload blocked by WAF. Trying alternate encoding..."
🤖 AI: "SUCCESS! Chaining SQLi → Auth Bypass → Data Extraction"
```

**Think XBow, but open-source and customizable.**


---

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ____  ____  ____  _  __                                      ║
║ /  __\/  __\/  _ \/ |/ /                                      ║
║ | | //|  \/|| / \||   /                                       ║
║ | |_\\|    /| \_/||   \                                       ║
║ \____/\_/\_\\____/\_|\_\                                      ║
║                                                              ║
║          Autonomous Penetration Testing Agent                ║
║                      v0.1.0                                  ║
╚══════════════════════════════════════════════════════════════╝
```

##  Features

###  **True AI Intelligence** - Not Just Another Scanner!

Brok doesn't run scripts - it **THINKS** like a pentester:

- **Reasons & Explains**: AI analyzes targets and explains WHY it's testing each thing
- **Context-Aware**: Detects tech stack and crafts specific payloads (e.g., MySQL vs PostgreSQL SQLi)
- **Adapts in Real-Time**: Learns from responses and modifies strategy on the fly
- **Chains Techniques**: Intelligently combines multiple attack vectors
- **Creative Problem-Solving**: Finds non-obvious vulnerabilities by thinking creatively

### **Comprehensive Security Testing**

-  **OWASP Top 10 Coverage**: SQLi, XSS, CSRF, Auth, Access Control, and more
-  **Intelligent Tools**: AI-driven reconnaissance, adaptive payload generation, smart bypasses
-  **MCP Integration**: Playwright browser automation + custom pentesting tools

###  **Beautiful Interfaces**

-  **Interactive TUI**: Watch the AI think in real-time - see its reasoning, tool usage, and analysis
-  **Modern Web Dashboard**: React + Tailwind dashboard for monitoring and reporting
-  **Rich Terminal Output**: Color-coded, easy-to-read results

###  **Safe & Compliant**

-  **Multi-Layer Authorization**: Target validation, whitelisting, and scope enforcement
-  **Risk Approval System**: User confirmation required for risky actions
-  **Complete Audit Trail**: Detailed logging of all actions and decisions
-  **Learning System**: RAG-powered knowledge base learns from past scans

##  Quick Start

### Prerequisites

- Python 3.11+ 
- Node.js 18+ (for web dashboard)
- Supabase account (for RAG/knowledge base)
- API key for at least one LLM provider:
  - OpenAI API key, OR
  - OpenRouter API key, OR  
  - Google Gemini API key

### Installation (5 minutes)

```bash
# 1. Clone and navigate
git clone <repository-url>
cd brok

# 2. Install dependencies
make install

# 3. Setup environment
make setup
# Then edit .env with your API keys

# 4. Launch interactive TUI
make run-tui
```

**Or use manual setup:**

```bash
# Install Python dependencies
pip install -r requirements.txt
playwright install

# Setup environment
cp .env.example .env
# Edit .env with your credentials

# Initialize database
python -m backend.scripts.init_db

# Install dashboard
cd dashboard && npm install && cd ..

# Run the TUI
python -m cli.main tui
```

##  Interactive TUI

Launch the beautiful terminal interface:

```bash
python -m cli.main tui
```

Features:
-  Real-time scan progress visualization
-  Live vulnerability discovery updates
-  Activity log stream
-  Interactive approval prompts for risky actions
-  Intuitive menu navigation
-  Fast and responsive

Perfect for both beginners and advanced users!

##  CLI Usage

```bash
# Start a scan
python -m cli.main scan https://example.com --mode normal

# Scan modes: quick, normal, deep, targeted

# Manage authorized targets
python -m cli.main auth add example.com
python -m cli.main auth list
python -m cli.main auth remove example.com

# View scan history
python -m cli.main history --limit 10
python -m cli.main history --scan-id <scan-id>

# Generate reports
python -m cli.main report <scan-id> --format html --output report.html

# Search knowledge base
python -m cli.main kb search "SQL injection"
python -m cli.main kb init  # Populate with defaults
```


Access at: **http://localhost:5173**

Dashboard features:
- 📊 Real-time scan monitoring via WebSockets
- 📈 Vulnerability statistics and charts
- 🎯 Scan management interface
- 📄 Report generation (HTML, JSON, PDF)
- 🔍 Knowledge base search
- ⚙️ Settings and configuration
- 🎨 Modern dark-themed UI

## 🏗️ Architecture

```
brok/
├── backend/
│   ├── agent/              # AI agent core with LangGraph
│   │   ├── orchestrator.py   # Main agent logic
│   │   ├── providers.py      # LLM provider abstraction
│   │   └── tools.py          # Agent tools
│   ├── mcp_servers/        # MCP server implementations
│   │   ├── playwright_server.py   # Browser automation
│   │   └── pentest_tools_server.py # Pentesting tools
│   ├── pentest/            # Vulnerability modules
│   │   ├── reconnaissance.py
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   ├── csrf.py
│   │   ├── auth.py
│   │   └── access_control.py
│   ├── rag/                # RAG system
│   │   ├── knowledge_base.py
│   │   ├── scan_history.py
│   │   └── supabase_client.py
│   ├── api/                # FastAPI REST API
│   │   └── main.py
│   └── auth/               # Authorization system
│       ├── manager.py
│       └── validator.py
├── cli/                    # CLI interface
│   ├── main.py            # CLI entry point
│   ├── tui.py             # Interactive TUI
│   └── commands/          # Command modules
├── dashboard/              # React web UI
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── pages/         # Dashboard pages
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── config/                 # Configuration files
│   └── authorized_targets.yaml
└── knowledge_base/         # Pentesting knowledge
```

##  Testing Capabilities

### OWASP Top 10 Coverage

1.  **Injection Attacks**
   - SQL injection
   - NoSQL injection
   - Command injection
   - LDAP injection

2.  **Broken Authentication**
   - Weak credentials
   - Session management
   - Password security
   - MFA bypass

3. **Sensitive Data Exposure**
   - Unencrypted data
   - Weak encryption
   - Information disclosure
   - Exposed config files

4.  **XML External Entities (XXE)**
   - XXE injection
   - XML parsing vulnerabilities

5.  **Broken Access Control**
   - IDOR (Insecure Direct Object References)
   - Privilege escalation
   - Forced browsing

6.  **Security Misconfiguration**
   - Default credentials
   - Debug mode enabled
   - Missing security headers
   - Directory listing

7.  **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

8.  **Insecure Deserialization**
   - Object injection
   - Deserialization attacks

9.  **Using Components with Known Vulnerabilities**
   - Outdated libraries
   - CVE detection

10.  **Insufficient Logging & Monitoring**
    - Error message analysis
    - Security event logging

##  Safety & Legal

###  CRITICAL WARNING

**This tool is for AUTHORIZED TESTING ONLY.**

-  **DO NOT** scan targets without explicit written permission
-  **DO NOT** use for unauthorized testing or malicious purposes
-  Unauthorized penetration testing is **ILLEGAL** in most jurisdictions
-  Always maintain proper authorization documentation

### Built-in Safety Features

1. **Authorization System**
   - Targets must be explicitly authorized
   - Scope validation
   - Pattern-based access control
   - Whitelist management

2. **Approval Checkpoints**
   - User approval required for risky actions
   - Risk level assessment (SAFE, MODERATE, RISKY)
   - Clear action descriptions

3. **Rate Limiting**
   - Prevents overwhelming target servers
   - Configurable request rates
   - Automatic throttling

4. **Comprehensive Logging**
   - All actions logged
   - Audit trail maintained
   - Evidence preservation

Read [SECURITY.md](SECURITY.md) for complete guidelines.

## 📚 Documentation

- **[Installation Guide](INSTALL.md)** - Detailed setup instructions
- **[User Guide](USER_GUIDE.md)** - Complete usage documentation
- **[Security Guidelines](SECURITY.md)** - Legal and safety information
- **[API Documentation](docs/API.md)** - REST API reference

## 🔧 Configuration

### Environment Variables (.env)

```bash
# LLM Provider
OPENAI_API_KEY=sk-...
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini

# Supabase
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=eyJxxx...

# Application
FASTAPI_HOST=0.0.0.0
FASTAPI_PORT=8000
MAX_CONCURRENT_SCANS=3
RATE_LIMIT_PER_SECOND=10
```

### Authorized Targets (config/authorized_targets.yaml)

```yaml
authorized_targets:
  - domain: "example.com"
    scope_patterns:
      - "*example.com*"
    excluded_patterns:
      - "*/logout"
      - "*/delete*"
    notes: "Approved by security team"

global_whitelist:
  - "localhost"
  - "127.0.0.1"
```

##  Use Cases

1. **Regular Security Audits**
   - Schedule periodic scans
   - Track vulnerability trends
   - Verify fixes

2. **Pre-Deployment Testing**
   - CI/CD integration
   - Automated security checks
   - Release validation

3. **Bug Bounty Programs**
   - Systematic vulnerability discovery
   - Comprehensive coverage
   - Detailed reporting

4. **Security Training**
   - Learn pentesting techniques
   - Understand vulnerabilities
   - Practice remediation

5. **Compliance Testing**
   - OWASP compliance
   - Industry standards
   - Regulatory requirements

##  Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request


##  Acknowledgments

- OWASP for security testing guidelines
- LangChain/LangGraph for agent framework
- Supabase for vector database
- React and Tailwind CSS for dashboard UI
- Rich library for beautiful TUI

## ⚡ Roadmap

- [ ] Additional vulnerability modules
- [ ] Mobile app testing
- [ ] API-specific testing modes
- [ ] GraphQL security testing
- [ ] Kubernetes/container scanning
- [ ] CI/CD plugins
- [ ] Custom plugin system
- [ ] Machine learning for false positive reduction
- [ ] Collaborative features
- [ ] Cloud deployment options



## Show Your Support

If you find Brok useful, please consider:
-  Starring the repository
-  Reporting bugs
-  Suggesting features
-  Contributing code
-  Sharing with others

---

**Made with ❤️ for the security community**

*Remember: Use responsibly and ethically. Always get proper authorization.*

