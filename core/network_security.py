"""Network security: IP detection, geolocation, and VPN/Proxy blocking."""
import json
import socket
import urllib.request
from datetime import datetime
from typing import Optional
from core.audit import log_action
from core.database import get_connection
VPN_PROXY_HEADERS = ('X-Forwarded-For', 'Via', 'X-Real-IP', 'Forwarded', 'X-ProxyUser-IP', 'CF-Connecting-IP')
_PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '::1', '0.0.0.0')

def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    ip = ip.strip()
    return any((ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES))

def get_client_ip(request_obj) -> str:
    """Extract the real client IP from a Flask request."""
    forwarded = request_obj.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = request_obj.headers.get('X-Real-IP', '')
    if real_ip:
        return real_ip.strip()
    return request_obj.remote_addr or 'unknown'

def detect_proxy_headers(request_obj) -> list[str]:
    """Detect suspicious proxy/VPN headers in the request."""
    found = []
    for header in VPN_PROXY_HEADERS:
        value = request_obj.headers.get(header)
        if value:
            found.append(f'{header}: {value}')
    return found

def get_ip_info(ip: str) -> dict:
    """Fetch geolocation and VPN/proxy status for an IP address.
    
    Uses the free ip-api.com service. Returns a dict with:
    - country, regionName, city, isp, org
    - proxy (bool): True if detected as VPN/proxy
    - hosting (bool): True if detected as hosting/datacenter IP
    """
    result = {'ip': ip, 'country': None, 'regionName': None, 'city': None, 'isp': None, 'org': None, 'proxy': False, 'hosting': False, 'query_success': False, 'is_private': _is_private_ip(ip)}
    if _is_private_ip(ip):
        try:
            from core.offline_geoip import check_offline_vpn
            offline_result = check_offline_vpn(ip)
            result.update(offline_result)
        except Exception:
            result['proxy'] = True
            result['query_success'] = False
        return result
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,proxy,hosting,query'
        req = urllib.request.Request(url, headers={'User-Agent': 'UjajaSign/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
        if data.get('status') == 'success':
            result.update({'country': data.get('country'), 'regionName': data.get('regionName'), 'city': data.get('city'), 'isp': data.get('isp'), 'org': data.get('org'), 'proxy': bool(data.get('proxy', False)), 'hosting': bool(data.get('hosting', False)), 'query_success': True})
        else:
            raise Exception('API query failed')
    except Exception:
        try:
            from core.offline_geoip import check_offline_vpn
            offline_result = check_offline_vpn(ip)
            result.update(offline_result)
        except Exception:
            result['proxy'] = True
            result['hosting'] = True
            result['query_success'] = False
    return result

def check_vpn_status(request_obj, user_id: Optional[int]=None) -> dict:
    """Full network security check for a request.
    
    Returns:
        dict with keys:
        - ip: client IP
        - ip_info: geolocation data
        - proxy_headers: list of suspicious headers found
        - is_vpn: True if VPN/proxy detected
        - is_blocked: True if access should be denied
        - reason: human-readable reason if blocked
        - access_time: ISO timestamp of the check
    """
    client_ip = get_client_ip(request_obj)
    access_time = datetime.now().isoformat(timespec='seconds')
    proxy_headers = detect_proxy_headers(request_obj)
    ip_info = get_ip_info(client_ip)
    is_vpn = ip_info['proxy'] or ip_info['hosting']
    has_proxy_headers = False
    if is_vpn:
        is_blocked = True
        reason = f"Akses diblokir: Terdeteksi penggunaan VPN/Proxy atau pengecekan gagal (Fail-Secure). IP: {client_ip}, ISP: {ip_info.get('isp', 'unknown')}, Lokasi: {ip_info.get('city', '?')}, {ip_info.get('country', '?')}."
    elif has_proxy_headers:
        is_blocked = True
        reason = f'Akses diblokir: Terdeteksi proxy header mencurigakan. IP: {client_ip}.'
    else:
        is_blocked = False
        reason = None
    _log_network_access(user_id=user_id, ip=client_ip, country=ip_info.get('country'), region=ip_info.get('regionName'), city=ip_info.get('city'), isp=ip_info.get('isp'), is_vpn=is_vpn, is_blocked=is_blocked, access_time=access_time)
    return {'ip': client_ip, 'ip_info': ip_info, 'proxy_headers': proxy_headers, 'is_vpn': is_vpn, 'is_blocked': is_blocked, 'reason': reason, 'access_time': access_time}

def _log_network_access(user_id: Optional[int], ip: str, country: Optional[str], region: Optional[str], city: Optional[str], isp: Optional[str], is_vpn: bool, is_blocked: bool, access_time: str) -> None:
    """Log network access details to the audit log."""
    vpn_label = 'VPN/Proxy' if is_vpn else 'Direct'
    blocked_label = 'BLOCKED' if is_blocked else 'ALLOWED'
    description = f"[{blocked_label}] Network access: IP={ip}, Lokasi={city or '?'}, {region or '?'}, {country or '?'}, ISP={isp or '?'}, Tipe={vpn_label}, Waktu={access_time}"
    log_action(user_id, 'NETWORK_ACCESS_CHECK', description)