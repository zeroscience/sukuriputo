import re

def run(file_path, text, directives):
    issues = []

    # Detect Kubernetes ingress configurations
    if "nginx.ingress.kubernetes.io" in text or "kubernetes.io/ingress.class" in text:
        issues.append({
            "severity": "LOW",
            "title": "Kubernetes ingress environment detected",
            "description": "Configuration contains Kubernetes ingress annotations",
            "lineno": "",
            "snippet": "",
            "rule": "k8s:ingress_detected"
        })

    # Missing real_ip_header when behind service load balancers
    if "X-Forwarded-For" in text and "real_ip_header" not in text:
        issues.append({
            "severity": "MEDIUM",
            "title": "Missing real_ip_header for Kubernetes LB",
            "description": "Client IP spoofing possible behind Kubernetes LoadBalancer",
            "lineno": "",
            "snippet": "",
            "rule": "k8s:real_ip_missing"
        })

    # Check ingress TLS misalignment
    if "listen 443" in text and "nginx.ingress.kubernetes.io/ssl-redirect" in text:
        if "ssl_certificate" not in text:
            issues.append({
                "severity": "HIGH",
                "title": "HTTPS misconfigured in Kubernetes ingress",
                "description": "TLS redirect enabled but no SSL certificate configured",
                "lineno": "",
                "snippet": "",
                "rule": "k8s:missing_cert"
            })

    return issues
