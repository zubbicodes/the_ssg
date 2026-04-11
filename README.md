# 🛡️ The SSG — WordPress Security Plugin

> Built by **Stratonally Dev Team**

A professional-grade WordPress security plugin designed for agencies and developers managing multiple client sites. Protects against attacks, locks down user registration, enforces admin IP whitelisting, logs all traffic with threat detection, scans for malware and SEO injection, and sends real-time alerts to Discord.

---

## Features

### 🔒 Registration Lockdown
- Disables new user registration globally across all entry points
- Blocks registration via the login form, REST API, and XML-RPC
- Automatically deletes any user account that bypasses the lock

### 🛡️ Admin IP Whitelist
- Restricts access to `wp-admin` and `wp-login.php` to whitelisted IPs only
- Blocked requests are logged and Discord-notified instantly
- Emergency bypass URL generated on activation — access from any IP if you get locked out
- Configurable redirect for blocked visitors (instead of default 403 page)

### ⚡ XML-RPC Blocking
- Disables the XML-RPC API entirely
- Cuts off a major brute-force and DDoS attack vector
- Returns a proper XML error response to automated tools

### 📋 Traffic Logging
- Logs every HTTP request with IP, method, URI, user agent, referrer, and HTTP status
- Threat scoring system (0–100) on every request
- Detects 11+ attack categories per request in real time
- Configurable log retention (default 30 days, auto-cleanup daily)
- Filterable log viewer with IP search, date range, suspicious/blocked filters

### 🔐 Brute Force Detection
- Tracks failed login attempts per IP in a rolling time window
- Configurable threshold and window (default: 5 fails in 10 minutes)
- Discord alert fires on first fail and again when threshold is reached

### 🔍 Security Scanner
Scans your site on demand for:

| Category | What it finds |
|---|---|
| **PHP Malware** | `eval(base64_decode`, `eval(gzinflate`, `preg_replace /e`, shell/exec with user input, obfuscated code |
| **PHP in Uploads** | Any `.php` file in `wp-content/uploads` (always a backdoor) |
| **SEO Injection** | Pharma hack, casino spam, hidden links (`display:none`), injected iframes |
| **Database Injection** | Injected scripts in posts, pages, widgets, options table |
| **Suspicious Users** | Admin accounts created in the last 30 days |
| **Recently Modified** | Files changed in the last 14 days (attacker traces) |

- **Full scan** — active theme + all active plugins + uploads + database
- **Quick scan** — theme + uploads + database only
- Dismiss false positives so they don't appear in future scans
- Sends a Discord alert if critical issues are found

### 🔔 Discord Alerts
Rich embed notifications sent to your Discord channel for:
- Blocked access attempts (IP whitelist, XML-RPC)
- Failed login attempts
- Brute force threshold reached
- Scanner/attack tool detected
- Suspicious high-score requests
- Security scan critical findings

---

## Threat Detection Patterns

Every incoming request is analysed against these categories:

| Pattern | Description |
|---|---|
| SQL Injection | `UNION SELECT`, `OR 1=1`, `benchmark()`, `sleep()` and more |
| XSS | `<script>`, `javascript:`, inline event handlers, `document.cookie` |
| Path Traversal | `../`, `%2e%2e%2f`, double-encoded variants |
| RCE | `phpinfo`, `system`, `exec`, backtick execution |
| Scanner User-Agents | sqlmap, nikto, havij, Burp Suite, masscan, dirbuster, 25+ tools |
| Sensitive Path Probe | `.env`, `wp-config`, `phpMyAdmin`, webshell paths, backup files |
| XML-RPC Access | Any hit on `xmlrpc.php` |
| No User-Agent | Automated requests with no UA string |
| Unusual HTTP Methods | Non-standard methods like `TRACE`, `CONNECT`, `PATCH` |

---

## Installation

### Via WordPress Admin
1. Download `fortress-security.zip`
2. Go to **Plugins → Add New → Upload Plugin**
3. Upload the zip and click **Install Now → Activate**

### Via cPanel / FTP
1. Extract `fortress-security.zip`
2. Upload the `fortress-security/` folder to `/wp-content/plugins/`
3. Go to **Plugins → Activate**

### ⚠️ After Activating — Do This First

> If you enable the IP Whitelist without adding your IP first, you will lock yourself out.

1. Go to **The SSG → IP Manager**
2. Click **"Use My IP"** to add your current IP address
3. Then go to **Settings** and enable the IP Whitelist

---

## Screenshots

| Dashboard | Traffic Logs |
|---|---|
| Live stats, recent threats, threat breakdown chart | Paginated log table with filters |

| Security Scanner | Settings |
|---|---|
| Findings grouped by severity with code snippets | Toggle-based settings with Discord integration |

---

## Plugin Structure

```
fortress-security/
├── fortress-security.php          # Plugin entry point
├── includes/
│   ├── class-db.php               # Database schema, queries, helpers
│   ├── class-firewall.php         # IP whitelist, registration lock, XML-RPC block
│   ├── class-logger.php           # Request logging, login tracking
│   ├── class-detector.php         # Real-time threat pattern analysis
│   ├── class-scanner.php          # On-demand file & database scanner
│   ├── class-discord.php          # Discord webhook notifications
│   └── class-admin.php            # Admin menus, pages, AJAX handlers
└── admin/
    ├── views/
    │   ├── dashboard.php          # Dashboard page
    │   ├── logs.php               # Traffic logs page
    │   ├── scanner.php            # Security scanner page
    │   ├── ip-manager.php         # IP whitelist manager
    │   ├── settings.php           # Settings page
    │   └── partials/header.php    # Shared nav header
    ├── css/fortress-admin.css     # Admin styles
    └── js/fortress-admin.js       # Admin scripts
```

---

## Requirements

- WordPress 5.0+
- PHP 7.2+
- MySQL 5.6+

---

## Developer Notes

- All DB queries use `$wpdb->prepare()` — no raw SQL with user input
- All form submissions use WordPress nonces
- All admin pages check `manage_options` capability
- Settings stored in `wp_options` with `fortress_` prefix
- Log data stored in `wp_fortress_logs` custom table
- IP whitelist stored in `wp_fortress_ip_whitelist` custom table
- Tables created via `dbDelta()` on activation with auto-repair on admin load

---

## License

GPL v2 or later — free to use, modify, and distribute.

---

*Built with ❤️ by [Stratonally Dev Team](https://github.com/zubbicodes)*
