"""
IP Geolocation utility.

Resolution order:
  1. Built-in table (covers all sample log IPs, works offline)
  2. Disk cache from previous live lookups
  3. Live lookup via ip-api.com (free tier, no key needed)

The haversine_km() function is used by the impossible-travel detector
to calculate great-circle distance between two lat/lon pairs.
"""
import json
import math
import os
import time
from typing import Dict, Optional, Tuple

# city, country, lat, lon
_KNOWN: Dict[str, Tuple[str, str, float, float]] = {
    # Sample log IPs
    "185.220.101.45": ("Frankfurt", "Germany", 50.1109, 8.6821),
    "185.220.101.46": ("Frankfurt", "Germany", 50.1109, 8.6821),
    "185.220.101.47": ("Frankfurt", "Germany", 50.1109, 8.6821),
    "203.0.113.50":   ("Beijing",   "China",   39.9042, 116.4074),
    "203.0.113.51":   ("Shanghai",  "China",   31.2304, 121.4737),
    "203.0.113.52":   ("Chengdu",   "China",   30.5728, 104.0668),
    "45.33.32.156":   ("Fremont",   "United States", 37.5485, -121.9886),
    "8.8.8.8":        ("Mountain View", "United States", 37.4223, -122.0843),
    "1.1.1.1":        ("Sydney",    "Australia", -33.8688, 151.2093),
    "91.108.4.1":     ("Amsterdam", "Netherlands", 52.3676, 4.9041),
    "91.108.4.2":     ("Amsterdam", "Netherlands", 52.3676, 4.9041),
    "195.154.0.1":    ("Paris",     "France",  48.8566, 2.3522),
    "31.220.0.1":     ("London",    "United Kingdom", 51.5074, -0.1278),
    # Private / loopback — resolved to None by is_private_ip()
}

_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", ".geoip_cache.json")
_cache: Dict[str, dict] = {}


def _load_cache() -> None:
    global _cache
    try:
        if os.path.exists(_CACHE_FILE):
            with open(_CACHE_FILE, "r") as fh:
                _cache = json.load(fh)
    except (json.JSONDecodeError, OSError):
        _cache = {}


def _save_cache() -> None:
    try:
        with open(_CACHE_FILE, "w") as fh:
            json.dump(_cache, fh)
    except OSError:
        pass


_load_cache()


def is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918, loopback, and link-local addresses."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or (a == 169 and b == 254)
        )
    except ValueError:
        return True


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two coordinate pairs."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def lookup_ip(ip: str) -> Optional[Dict]:
    """
    Return {'city', 'country', 'lat', 'lon'} for a public IP, or None.
    """
    if not ip or is_private_ip(ip):
        return None

    if ip in _KNOWN:
        city, country, lat, lon = _KNOWN[ip]
        return {"city": city, "country": country, "lat": lat, "lon": lon}

    if ip in _cache:
        return _cache[ip]

    # Live lookup (fails gracefully if offline)
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "city":    data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
                "lat":     data.get("lat", 0.0),
                "lon":     data.get("lon", 0.0),
            }
            _cache[ip] = result
            _save_cache()
            time.sleep(0.1)  # stay within free-tier rate limit
            return result
    except Exception:
        pass

    return None
