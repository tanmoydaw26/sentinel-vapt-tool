from datetime import datetime
from core.models import ScanResult
from core.http_client import HTTPClient
from core.plugin_loader import PluginLoader
from core.analyzer import SmartAnalyzer
from utils.logger import SplunkLogger
from utils.helpers import normalize_target

class ScanEngine:
    def __init__(self, target, safe_mode=True, ports=None):
        self.target = normalize_target(target)
        self.safe_mode = safe_mode
        self.ports = ports or []
        self.client = HTTPClient(safe_mode=safe_mode)
        self.loader = PluginLoader()
        self.analyzer = SmartAnalyzer()
        self.logger = SplunkLogger()

    def run(self):
        result = ScanResult(target=self.target, started_at=datetime.utcnow().isoformat())
        context = {
            'target': self.target,
            'safe_mode': self.safe_mode,
            'ports': self.ports,
            'client': self.client,
            'result': result,
            'logger': self.logger
        }
        modules = self.loader.default_modules()
        for module in modules:
            self.logger.log('INFO', 'module_started', self.target, {'module': module.name})
            try:
                output = module.run(context)
                if isinstance(output, list):
                    for item in output:
                        if hasattr(item, 'title') and hasattr(item, 'cvss_score'):
                            result.add_finding(item)
                self.logger.log('INFO', 'module_finished', self.target, {'module': module.name, 'items': len(output) if isinstance(output, list) else 0})
            except Exception as e:
                self.logger.log('ERROR', 'module_error', self.target, {'module': module.name, 'error': str(e)})

        result.findings = self.analyzer.reduce_false_positives(result.findings)
        result.findings = self.analyzer.correlate(result.findings)
        result.findings = self.analyzer.dynamic_risk(result.findings)
        for finding in result.findings:
            finding.tags.append('safe-mode' if self.safe_mode else 'active')
        result.finished_at = datetime.utcnow().isoformat()
        result.logs = self.logger.events
        return result
