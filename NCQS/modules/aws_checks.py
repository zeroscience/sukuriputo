import re

def run(file_path, text, directives):
    issues = []

    # Behind ALB/NLB but missing real_ip_header
    if ("X-Forwarded-For" in text or "X-Forwarded-Proto" in text) and \
       "real_ip_header" not in text:
        issues.append({
            "severity": "HIGH",
            "title": "Missing real_ip_header behind AWS Load Balancer",
            "description": "Allows spoofing of source IP addresses",
            "lineno": "",
            "snippet": "",
            "rule": "aws:missing_real_ip_header"
        })

    # CloudFront origin usage
    if ".cloudfront.net" in text or "s3.amazonaws.com" in text:
        if "proxy_set_header Host" not in text:
            issues.append({
                "severity": "MEDIUM",
                "title": "Missing Host rewrite for AWS CloudFront/S3 origin",
                "description": "Origin may fail without explicit Host header",
                "lineno": "",
                "snippet": "",
                "rule": "aws:missing_host_rewrite"
            })

    # Public EC2 exposure
    if "listen 0.0.0.0:80" in text or "listen 0.0.0.0:443" in text:
        if "limit_req" not in text and "limit_conn" not in text:
            issues.append({
                "severity": "MEDIUM",
                "title": "Public EC2 listener with no rate limiting",
                "description": "Missing rate limits on public-facing EC2 ports",
                "lineno": "",
                "snippet": "",
                "rule": "aws:no_rate_limiting"
            })

    return issues
