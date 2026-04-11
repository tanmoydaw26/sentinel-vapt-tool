import time
import requests
from utils.helpers import random_header

class HTTPClient:
    def __init__(self, timeout=8, delay=0.4, safe_mode=True):
        self.timeout = timeout
        self.delay = delay
        self.safe_mode = safe_mode
        self.session = requests.Session()

    def request(self, method, url, **kwargs):
        headers = kwargs.pop('headers', {})
        merged = random_header()
        merged.update(headers)
        time.sleep(self.delay)
        return self.session.request(method, url, headers=merged, timeout=self.timeout, allow_redirects=False, **kwargs)
