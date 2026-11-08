# HAZARUS Telegram Bot Integration Plan

## 📋 Architecture Overview

```
Telegram Bot → Telegram Bot Module → HAZARUS Core → Interactive Mode
                    ↓
              Menu State Manager
                    ↓
              UI Renderer (Inline Buttons, Icons)
                    ↓
              Command Handlers (Async)
```

## 1. Directory Structure

```
hazarus/
├── telegram/                    # NEW MODULE
│   ├── __init__.py
│   ├── bot.py                 # Main Telegram bot entry point
│   ├── menu.py                # Menu definitions and state management
│   ├── ui.py                  # UI rendering (buttons, icons, formatting)
│   ├── handlers.py             # Command handlers for each menu option
│   ├── config.py              # Telegram bot configuration
│   ├── session.py             # User session management
│   └── keyboard.py            # Inline keyboard layouts
```

## 2. Technology Stack

- **Library:** `python-telegram-bot` (extensive, well-documented)
- **Async:** `asyncio` for non-blocking operations
- **Icons:** Emoji for UI elements
- **UI Components:** Inline keyboards, formatted text (Markdown/HTML)
- **State Management:** In-memory per-user state with optional persistence

## 3. Core Components

### 3.1 Telegram Bot Entry Point (`bot.py`)
- Initialize bot with token from config
- Register command handlers (/start, /help, /privacy, etc.)
- Handle callback queries (button clicks)
- Delegate to menu system

### 3.2 Menu System (`menu.py`)
- Define menu hierarchy mirroring InteractiveMode
- Track user's current menu position
- Handle menu navigation (back, home, etc.)
- Map menu items to command handlers

**Menu Structure:**
```
Main Menu:
├── [🎯] Target Management
├── [🔍] Reconnaissance
├── [📡] Network Scanning
├── [🌐] Web/API Assessment
├── [🛡️] Post-Assessment
├── [🔬] Source Code Analysis
├── [⚡] Exploitation
├── [📊] Reporting
├── [🔧] Configuration
├── [🔐] Privacy Check
└── [🎛️] Dashboard
```

### 3.3 UI Renderer (`ui.py`)
- Render inline keyboards with icons
- Format messages with Markdown/HTML
- Display ICSE banner with styling
- Render progress indicators
- Format scan results
- Handle long output with pagination

### 3.4 Command Handlers (`handlers.py`)
- Async wrappers around existing InteractiveMode methods
- Input validation
- Progress updates during long operations
- Result formatting for Telegram
- Error handling with user-friendly messages

### 3.5 Session Management (`session.py`)
- Track user state (current menu, collected inputs)
- Store user-specific data (targets, preferences)
- Session timeout handling
- Optional database persistence

### 3.6 Keyboard Layouts (`keyboard.py`)
- Define inline keyboard layouts for each menu
- Button icons and labels
- Navigation buttons (Back, Home, Cancel)

## 4. Features to Implement

### 4.1 ICSE Banner Display
- Display at bot start (/start command)
- Use ASCII art or styled text
- Include framework description
- Modern formatting with emojis

**Example:**
```
╔════════════════════════════════════════════════════════════╗
║  🔒 HAZARUS SECURITY ASSESSMENT FRAMEWORK 🔒              ║
║  🚀 ADVANCED SECURITY PLATFORM                                 ║
║  📱 INTERACTIVE MODE ONLY                                      ║
╚════════════════════════════════════════════════════════════╝
```

### 4.2 Main Menu Navigation
- Inline buttons with icons
- Submenu navigation
- Back to main menu option
- Help/About option

### 4.3 Input Collection
- Target input (IP, domain, URL)
- Options selection (timing, scan type, etc.)
- Confirmation prompts
- Validation with error messages

### 4.4 Command Execution
- Execute HAZARUS commands via InteractiveMode
- Async execution with progress updates
- Display "Scanning..." messages
- Show intermediate results

### 4.5 Result Display
- Formatted scan results
- Tables for findings
- Summary statistics
- Downloadable reports (if supported)

### 4.6 Privacy Integration
- Mandatory privacy check before operations
- Anonsurf status
- DNS leak check
- IPv6 exposure check
- Tor connectivity check

## 5. Configuration

### `hazarus/telegram/config.py`
```python
TELEGRAM_BOT_TOKEN = "your_bot_token_here"
ADMIN_USER_IDS = [123456789]  # Optional: Admin users
MAX_SESSION_DURATION = 3600  # 1 hour
ENABLE_REPORT_DOWNLOADS = True
```

### `hazarus/config/hazarus.yaml` (add section)
```yaml
telegram:
  enabled: true
  token: ${TELEGRAM_BOT_TOKEN}
  admin_users: []
  max_session_duration: 3600
```

## 6. Security Considerations

- Bot token stored in environment variable
- User authentication (optional: chat ID whitelist)
- Authorization checks before sensitive operations
- Privacy enforcement (Anonsurf required for certain operations)
- Rate limiting per user
- Command logging

## 7. Implementation Phases

### Phase 1: Basic Bot Setup
- Create telegram module structure
- Set up python-telegram-bot
- Implement /start command with banner
- Basic menu navigation

### Phase 2: Menu Integration
- Implement full menu hierarchy
- Add all submenu options
- Navigation buttons (Back, Home)
- UI rendering with icons

### Phase 3: Command Handlers
- Implement handlers for all menu options
- Integrate with existing InteractiveMode methods
- Input collection and validation
- Async execution

### Phase 4: Privacy & Authorization
- Integrate privacy checks
- Authorization validation
- Scope checking
- Safety gates

### Phase 5: Result Display
- Format scan results
- Pagination for long output
- Progress updates
- Error handling

### Phase 6: Advanced Features
- Report downloads
- Multi-language support
- User preferences
- Session persistence

## 8. CLI Integration

Add new CLI command:
```bash
hazarus telegram start    # Start Telegram bot
hazarus telegram stop     # Stop Telegram bot
hazarus telegram status    # Check bot status
```

## 9. Example User Flow

```
User: /start
Bot: [ICSE Banner displayed]
     Main Menu:
     [🎯] Targets
     [🔍] Recon
     [📡] Network Scan
     ...

User: [🔍] Recon
Bot: Reconnaissance Menu:
     [🌐] DNS Recon
     [🎯] Subdomains
     [📋] WHOIS
     [🔙] Back

User: [🌐] DNS Recon
Bot: Enter target (domain/IP):
User: example.com
Bot: Starting DNS reconnaissance...
     [Progress bar...]
     Results: [Formatted findings]
```

## 10. Dependencies to Add

Update `requirements.txt`:
```
python-telegram-bot==20.7
```

## 11. Pending User Decisions

1. **Bot Token:** Do you have a Telegram bot token ready, or should I add placeholder?
2. **Authentication:** Should the bot be public or restricted to specific users?
3. **Report Downloads:** Should users be able to download reports as files?
4. **Multi-language:** Do you need multi-language support?
5. **Concurrent Users:** Expected number of concurrent users?

## 12. Note

This plan preserves all core HAZARUS functionality and wraps it in a Telegram bot interface. The bot will essentially be a UI layer over the existing InteractiveMode, making it accessible via Telegram while maintaining all security controls, privacy checks, and authorization requirements.
