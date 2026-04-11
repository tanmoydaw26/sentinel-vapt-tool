import socket
from modules.base import BaseModule
from utils.helpers import COMMON_SUBDOMAINS, get_domain

class SubdomainEnumerator(BaseModule):
    name = 'subdomain_enum'
    category = 'recon'

    def run(self, context):
        domain = get_domain(context['target']).split(':')[0]
        parts = domain.split('.')
        if len(parts) < 2:
            return []
        root = '.'.join(parts[-2:])
        found = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f'{sub}.{root}'
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
            except Exception:
                continue
        context['result'].subdomains.extend(found)
        return found
