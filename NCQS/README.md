# nginx-conf-qs (NCQS) – Nginx Configuration Quick Scan

`nginx-conf-qs` is a static security scanner designed to audit Nginx configuration files and related infrastructure code. It performs a deep inspection of configuration directories and highlights misconfigurations that weaken security across Nginx, Kubernetes, AWS environments, and YAML-based deployment files.

## Core Capabilities

### Nginx Configuration Analysis
The scanner evaluates:
- SSL/TLS protocol strength
- Cipher suite security
- Certificate configuration issues
- Autoindex exposure
- Proxy and upstream configuration risks
- Misconfigured includes and recursive file structures

It processes single `.conf` files and full directory trees, automatically following Nginx-style includes.

## Extended Module System

Additional modules enhance coverage across cloud and containerized environments:

### Kubernetes (`k8s_checks`)
- Detects ingress definitions
- Flags TLS issues and missing certificates
- Identifies insecure annotations and exposure patterns

### AWS (`aws_checks`)
- Evaluates AWS Load Balancer configuration
- Detects CloudFront/S3 origin exposure
- Flags public EC2 risk indicators

### YAML Scanner (`yaml_scanner`)
Supports YAML infrastructure files, identifying:
- Exposed secrets
- NodePort and service exposure risks
- WireGuard and VPN configuration issues
- Kubernetes ingress and TLS problems

## Output Formats

The scanner generates multiple report types:
- **HTML** (light/dark toggle, color-coded severity)
- **JSON**
- **CSV**

Findings include:
- Severity classification
- Affected domain or hostname
- File location
- Proxy or ingress context
- Aggregated summaries per file

## Usage

Basic invocation:
```bash
./nginx-conf-qs.py -p /etc/nginx -r reports
```

Including additional modules:
```bash
./nginx-conf-qs.py -p /etc/nginx -r reports -m yaml_scanner -v
```

Key flags:
- `-p <path>` — target directory to scan
- `-r <output_dir>` — save reports to directory
- `-m <module>` — enable extra modules
- `-v` — verbose mode

## Project Summary

- **Type:** Single-file Python scanner with pluggable rule modules
- **Author:** Gjoko Krstic
- **Inspiration:** Gixy
- **Powered by:** SillySec.com
- **Version:** 16.11-43g (Codename: Delfina)
