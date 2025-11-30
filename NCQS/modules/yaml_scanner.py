import re

def run(file_path, text, directives):
    """
    YAML Scanner module for nginx-conf-qs.

    Args:
        file_path: full path to file (yaml/yml)
        text: file content
        directives: unused, kept for interface compatibility

    Returns:
        list of issues in the same format as builtin and other modules
    """

    issues = []

    # Only scan .yaml or .yml files
    if not (file_path.endswith(".yaml") or file_path.endswith(".yml")):
        return issues

    # ===========================
    # Raw regex-based secret scanning
    # ===========================
    SECRET_REGEXES = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws_secret_access_key[:\s]+([A-Za-z0-9/+=]{40})",
        "Generic Token": r"(?i)(token|secret|apikey|api_key|auth)[\"'\s:]+([A-Za-z0-9\.\-_]{16,})",
        "Private Key Block": r"-----BEGIN (RSA|EC|PRIVATE) KEY-----",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36}",
        "GitLab Token": r"glpat-[A-Za-z0-9\-_]{20,}",
    }

    for name, pattern in SECRET_REGEXES.items():
        for match in re.finditer(pattern, text):
            issues.append({
                "severity": "HIGH",
                "title": f"Potential exposed secret: {name}",
                "description": f"Regex match in YAML file: {name}",
                "lineno": text[:match.start()].count("\n") + 1,
                "snippet": match.group(0),
                "rule": "yaml:exposed_secret",
            })

    # ===========================
    # Kubernetes Ingress rules
    # ===========================
    ingress_pattern = re.compile(r"kind:\s*Ingress", re.IGNORECASE)
    if ingress_pattern.search(text):
        if "tls:" not in text:
            issues.append({
                "severity": "HIGH",
                "title": "Kubernetes Ingress without TLS",
                "description": "Ingress found but TLS section is missing",
                "lineno": None,
                "snippet": "",
                "rule": "yaml:ingress_no_tls",
            })

        # Wildcard hosts
        wildcard_host_pattern = re.compile(r"host:\s*\*\.", re.IGNORECASE)
        if wildcard_host_pattern.search(text):
            issues.append({
                "severity": "MEDIUM",
                "title": "Ingress uses wildcard host",
                "description": "Wildcard host can be risky",
                "lineno": None,
                "snippet": "",
                "rule": "yaml:ingress_wildcard_host",
            })

    # ===========================
    # VPN / WireGuard detection
    # ===========================
    if "wireguard" in text.lower() or "wg0" in text:
        issues.append({
            "severity": "HIGH",
            "title": "WireGuard/VPN configuration detected",
            "description": "YAML file references WireGuard/VPN settings",
            "lineno": None,
            "snippet": "",
            "rule": "yaml:wireguard_detected",
        })

    # ===========================
    # NodePort / Public exposure detection
    # ===========================
    if "NodePort" in text:
        issues.append({
            "severity": "MEDIUM",
            "title": "Kubernetes NodePort detected",
            "description": "Potential public exposure risk",
            "lineno": None,
            "snippet": "",
            "rule": "yaml:nodeport_detected",
        })

    return issues
