import json
import time
from datetime import datetime

class SplunkLogger:
    def __init__(self):
        self.events = []

    def log(self, level, event, target, details=None):
        payload = {
            'time': time.time(),
            'host': 'sentinel-vapt',
            'source': 'scanner',
            'sourcetype': '_json',
            'event': {
                'timestamp': datetime.utcnow().isoformat(),
                'level': level,
                'event_type': event,
                'target': target,
                'details': details or {}
            }
        }
        self.events.append(payload)
        return payload

    def export(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            for event in self.events:
                f.write(json.dumps(event) + '\n')
