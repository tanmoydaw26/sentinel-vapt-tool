from modules.base import BaseModule
from utils.helpers import COMMON_DIRS, make_url

class DirectoryBruteforcer(BaseModule):
    name = 'dir_bruteforce'
    category = 'recon'

    def run(self, context):
        client = context['client']
        found = []
        for path in COMMON_DIRS:
            url = make_url(context['target'], path)
            try:
                r = client.request('GET', url)
                if r.status_code in [200, 301, 302, 403]:
                    found.append(f'{url} [{r.status_code}]')
            except Exception:
                continue
        context['result'].directories.extend(found)
        return found
