import argparse
import os
from core.engine import ScanEngine
from reporting.report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description='Sentinel VAPT Framework')
    parser.add_argument('--target', required=True, help='Target URL or host')
    parser.add_argument('--full-scan', action='store_true', help='Run full safe-mode scan')
    parser.add_argument('--ports', help='Comma-separated custom ports')
    parser.add_argument('--unsafe', action='store_true', help='Disable safe mode')
    parser.add_argument('--output', default='output', help='Output directory')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    ports = [int(p.strip()) for p in args.ports.split(',')] if args.ports else None
    engine = ScanEngine(target=args.target, safe_mode=not args.unsafe, ports=ports)
    result = engine.run()

    reporter = ReportGenerator(result)
    reporter.generate_json(os.path.join(args.output, 'report.json'))
    reporter.generate_html(os.path.join(args.output, 'report.html'))
    reporter.generate_pdf(os.path.join(args.output, 'report.pdf'))
    engine.logger.export(os.path.join(args.output, 'splunk_events.jsonl'))

    print(f'Scan complete for {args.target}')
    print(f'Findings: {len(result.findings)}')
    print(f'Reports written to {args.output}/')

if __name__ == '__main__':
    main()
