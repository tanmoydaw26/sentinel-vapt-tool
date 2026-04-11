import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.base import BaseModule
from utils.helpers import COMMON_PORTS, get_domain

class PortScanner(BaseModule):
    name = 'port_scanner'
    category = 'network'

    def scan_port(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        try:
            result = s.connect_ex((host, port))
            if result == 0:
                return {'port': port, 'service': COMMON_PORTS.get(port, 'unknown'), 'state': 'open'}
        finally:
            s.close()
        return None

    def run(self, context):
        host = get_domain(context['target']).split(':')[0]
        ports = context.get('ports') or list(COMMON_PORTS.keys())
        found = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(self.scan_port, host, p) for p in ports]
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
        context['result'].open_ports.extend(sorted(found, key=lambda x: x['port']))
        return found
