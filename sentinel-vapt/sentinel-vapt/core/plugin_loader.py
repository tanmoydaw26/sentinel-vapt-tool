from modules.network.port_scanner import PortScanner
from modules.network.subdomain_enum import SubdomainEnumerator
from modules.web.dir_bruteforce import DirectoryBruteforcer
from modules.web.headers_check import HeaderCheck
from modules.web.sqli import SQLInjectionModule
from modules.web.xss import XSSModule
from modules.web.ssrf import SSRFModule
from modules.web.open_redirect import OpenRedirectModule
from modules.web.sensitive_data import SensitiveDataExposureModule
from modules.api.jwt_checks import JWTChecks
from modules.auth.weak_auth import WeakAuthModule
from modules.ad.ad_exploitation import ActiveDirectoryModule

class PluginLoader:
    def default_modules(self):
        return [
            PortScanner(),
            SubdomainEnumerator(),
            DirectoryBruteforcer(),
            HeaderCheck(),
            SQLInjectionModule(),
            XSSModule(),
            SSRFModule(),
            OpenRedirectModule(),
            SensitiveDataExposureModule(),
            JWTChecks(),
            WeakAuthModule(),
            ActiveDirectoryModule()
        ]
