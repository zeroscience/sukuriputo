"""
Example module for nginx-conf-qs
Place additional modules into the "modules/" directory. Module must expose a function:
    def run(file_path: str, text: str, directives: List[Dict]) -> List[Dict]:
which returns a list of issues in the same format used by the main scanner:
    {
      "severity": "HIGH"|"MEDIUM"|"LOW"|"INFO",
      "title": "...",
      "description": "...",
      "lineno": 123,           # optional
      "snippet": "line text",  # optional
      "rule": "example:rule",
      "context": ["server default", "location /"]
    }
This example flags use of "ssl_session_cache off" as INFO.
"""
def run(file_path, text, directives):
    issues = []
    for d in directives:
        if d['name'] == 'ssl_session_cache' and 'off' in d['value'].lower():
            issues.append({
                "severity": "INFO",
                "title": "ssl_session_cache disabled",
                "description": "ssl_session_cache is set to off; enabling it may improve SSL/TLS performance.",
                "lineno": d.get('lineno'),
                "snippet": d.get('value'),
                "rule": "example:ssl_session_cache_off",
                "context": d.get('context', [])
            })
    return issues
