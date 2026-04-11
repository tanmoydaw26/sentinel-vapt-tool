from flask import Flask, render_template
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    report_path = os.path.join(os.path.dirname(__file__), '..', 'output', 'report.json')
    data = {'target': 'No scan loaded', 'findings': [], 'open_ports': [], 'subdomains': [], 'directories': []}
    if os.path.exists(report_path):
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    return render_template('dashboard.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
