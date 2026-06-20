import os

def check_offline_vpn(ip: str) -> dict:
    """
    Dummy offline fallback using a local database (e.g., MaxMind GeoIP2).
    In a real scenario, this would query a local .mmdb file.
    """
    known_offline_proxies = {'10.0.0.99', '192.168.1.100'}
    is_proxy = ip in known_offline_proxies
    return {'country': 'Offline-Fallback', 'regionName': 'LocalDB', 'city': 'LocalDB', 'isp': 'Local ISP DB', 'org': 'Local Org DB', 'proxy': is_proxy, 'hosting': False, 'query_success': True}