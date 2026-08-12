"""Detection data for OSC: regex patterns, sensitive-file lists, risk levels.

Kept free of logic and heavy imports so every other module can import it safely.
"""

# Known high-signal secret prefixes: these bypass the entropy filter because the
# format itself is already strong evidence of a real credential.
KNOWN_SECRET_PREFIXES = (
    'sk_live_', 'sk_test_', 'rk_live_', 'rk_test_', 'akia', 'aiza', 'ya29.',
    'ghp_', 'gho_', 'ghs_', 'ghr_', 'github_pat_',
    'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-', 'sg.', 'eyj', '-----begin',
)

# Regex patterns: category -> list of (pattern, value_group, confidence).
# value_group 0 = whole match; otherwise the capture group holding the value.
# Assignment patterns carry an inline (?i) so only the KEY name is case-insensitive;
# fixed-format prefixes (AKIA, ghp_, eyJ, ...) stay case-sensitive on purpose.
PATTERNS = {
    'api_keys': [
        (r'(?i)["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']([^"\']{8,100})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:api[_-]?secret|secret[_-]?key|client[_-]?secret)["\']?\s*[=:]\s*["\']([^"\']{8,100})["\']', 1, 'medium'),
        # Unquoted (.env / config style) KEY=VALUE
        (r'(?i)(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)\s*[=:]\s*([A-Za-z0-9_\-]{12,100})', 1, 'medium'),
        (r'sk_(?:live|test)_[A-Za-z0-9]{16,}', 0, 'high'),
        (r'AKIA[0-9A-Z]{16}', 0, 'high'),
        (r'ya29\.[0-9A-Za-z\-_]+', 0, 'high'),
        (r'AIza[0-9A-Za-z\-_]{35}', 0, 'high'),
        (r'gh[pousr]_[A-Za-z0-9]{36,}', 0, 'high'),
        (r'github_pat_[A-Za-z0-9_]{60,}', 0, 'high'),
        (r'xox[baprs]-[A-Za-z0-9-]{10,}', 0, 'high'),
        (r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}', 0, 'high'),
    ],
    'tokens': [
        (r'(?i)["\']?(?:token|access[_-]?token|auth[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{12,300})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:refresh[_-]?token|bearer[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{12,300})["\']', 1, 'medium'),
        # Unquoted (.env / config style) token assignments
        (r'(?i)(?:access[_-]?token|auth[_-]?token|api[_-]?token)\s*[=:]\s*([A-Za-z0-9_\-.]{16,300})', 1, 'medium'),
        # Proper JWT: base64url header starting with eyJ, then two more segments
        (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 0, 'high'),
    ],
    'passwords': [
        (r'(?i)["\']?(?:password|passwd|pwd)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:db[_-]?password|database[_-]?pass)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'high'),
        (r'(?i)["\']?(?:passphrase)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'medium'),
        # Unquoted (.env / config style) password assignments
        (r'(?i)(?:password|passwd|db[_-]?password|database[_-]?pass)\s*[=:]\s*([^\s"\'<>&]{6,64})', 1, 'medium'),
    ],
    'database': [
        (r'(?i)["\']?(?:database[_-]?url|db[_-]?url|connection[_-]?string)["\']?\s*[=:]\s*["\']([^"\']+?)["\']', 1, 'high'),
        (r'(?:mysql|postgresql|postgres|mongodb|redis|mssql)://[^"\'\s<>]{4,}', 0, 'high'),
    ],
    'private_keys': [
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', 0, 'high'),
    ],
    'emails': [
        (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 0, 'low'),
    ],
    'internal_ips': [
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
        (r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
    ],
    'config_files': [
        (r'(?i)["\']?(?:config|configuration|settings)["\']?\s*[=:]\s*["\']([^"\']+?\.(?:json|ya?ml|ini|conf|config|php|py))["\']', 1, 'low'),
    ],
    'financial': [
        (r'(?i)(?:stripe|paypal|braintree)_(?:secret|key|token)["\']?\s*[=:]\s*["\']([^"\']{10,80})["\']', 1, 'high'),
        (r'rk_(?:live|test)_[A-Za-z0-9]{16,}', 0, 'high'),
    ],
}

# Extended sensitive files list (used both as discovery seeds and exposure checks)
SENSITIVE_FILES = [
    # Environment files
    '.env', '.env.local', '.env.production', '.env.development',
    # Configuration files
    'config.php', 'configuration.php', 'settings.php', 'wp-config.php',
    'config.json', 'settings.json', 'configuration.json',
    'config.yml', 'config.yaml', 'settings.yml', 'app.config',
    'web.config', '.htaccess', '.htpasswd',
    # Database files
    'database.yml', 'database.json', 'db.config',
    # Backup files
    '.bak', '.backup', '.old', '.tmp', '.temp', '.save',
    '.orig', '.copy', '.bk', '.back', '.swp',
    # Log files
    '.log', 'logs.txt', 'error.log', 'access.log',
    # Key files
    '.pem', '.key', '.crt', '.cert', '.pfx',
    'id_rsa', 'id_dsa', 'private.key',
    # Data files
    '.sql', '.db', '.sqlite', '.mdb',
    '.dump', '.export', '.dat',
    # VCS metadata
    '.git/config', '.git/HEAD', '.svn/entries', '.DS_Store',
]

# Risk level per finding category
RISK_LEVELS = {
    'api_keys': 'HIGH',
    'passwords': 'HIGH',
    'database': 'HIGH',
    'financial': 'HIGH',
    'tokens': 'HIGH',
    'private_keys': 'HIGH',
    'exposed_sensitive_file': 'MEDIUM',
    'config_files': 'MEDIUM',
    'internal_ips': 'MEDIUM',
    'sensitive_file_reference': 'LOW',
    'emails': 'LOW',
    # Web security posture (osc/security_audit.py) + passive crawl checks
    'tls_issues': 'HIGH',
    'cors_misconfiguration': 'HIGH',
    'directory_listing': 'MEDIUM',
    'security_headers': 'MEDIUM',
    'cookie_security': 'MEDIUM',
    'http_methods': 'MEDIUM',
    'open_redirect': 'MEDIUM',
    'tech_fingerprint': 'LOW',
    # Quick-win info-leak checks (osc/security_audit.py)
    'mixed_content': 'MEDIUM',
    'sri_missing': 'LOW',
    'security_txt_missing': 'LOW',
    'graphql_introspection': 'HIGH',
    # Recon (osc/recon.py)
    'subdomain_found': 'LOW',
    'open_port': 'MEDIUM',
    'waf_detected': 'LOW',
    # Active vulnerability probing (osc/active_scan.py)
    'xss_reflected': 'HIGH',
    'sqli_error': 'HIGH',
    'path_traversal': 'HIGH',
    'ssti': 'HIGH',
    'ssrf_candidate': 'LOW',
}
