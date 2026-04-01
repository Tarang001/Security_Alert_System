import re


def is_valid_ip(ip):
    """Checks if a string is a valid IPv4 address."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def validate_ips(ip_list):
    """
    Validates a list of IPs.
    Returns (deduplicated_valid_list, error_message).
    """
    if not ip_list:
        return [], "No IP addresses provided."

    invalid = [ip for ip in ip_list if not is_valid_ip(ip)]
    if invalid:
        return [], f"Invalid IP address(es): {', '.join(invalid)}"

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for ip in ip_list:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)

    return unique, None


def classify_ip(enriched):
    """
    Applies simple classification rules.
    Returns: 'Malicious', 'Suspicious', or 'Safe'
    """
    score = enriched.get("score", 0)
    isp = enriched.get("isp", "").lower()

    if score > 80:
        return "Malicious"
    if "tor" in isp:
        return "Suspicious"
    return "Safe"