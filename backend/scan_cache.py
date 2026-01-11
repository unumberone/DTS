"""
Scan Cache Module - Cache results by (sha256, method)
Prevents re-running inference when switching methods
"""

import hashlib
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from threading import Lock

@dataclass
class CacheEntry:
    """Single cache entry for scan result"""
    sha256: str
    method: str
    result: Dict
    timestamp: float
    file_size: int
    filename: str


class ScanCache:
    """
    Thread-safe cache for scan results
    Key: (sha256, method)
    """
    
    def __init__(self, max_entries: int = 1000, ttl_seconds: int = 3600):
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0
    
    def _make_key(self, sha256: str, method: str) -> str:
        return f"{sha256}:{method}"
    
    def get(self, sha256: str, method: str) -> Optional[Dict]:
        """Get cached result if exists and not expired"""
        key = self._make_key(sha256, method)
        
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            
            # Check TTL
            if time.time() - entry.timestamp > self.ttl_seconds:
                del self._cache[key]
                self._misses += 1
                return None
            
            self._hits += 1
            print(f"[CACHE HIT] {sha256[:16]}... method={method}")
            return entry.result
    
    def set(self, sha256: str, method: str, result: Dict, file_size: int, filename: str):
        """Store result in cache"""
        key = self._make_key(sha256, method)
        
        with self._lock:
            # Evict oldest if full
            if len(self._cache) >= self.max_entries:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].timestamp)
                del self._cache[oldest_key]
            
            self._cache[key] = CacheEntry(
                sha256=sha256,
                method=method,
                result=result,
                timestamp=time.time(),
                file_size=file_size,
                filename=filename
            )
            print(f"[CACHE SET] {sha256[:16]}... method={method}")
    
    def get_all_methods(self, sha256: str) -> Dict[str, Dict]:
        """Get cached results for all methods for a given file"""
        results = {}
        methods = ["lstm", "cnn_lstm", "transformer", "ensemble"]
        
        for method in methods:
            cached = self.get(sha256, method)
            if cached:
                results[method] = cached
        
        return results
    
    def get_stats(self) -> Dict:
        return {
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0
        }


def compute_sha256(file_bytes: bytes) -> str:
    """Compute SHA256 hash of file"""
    return hashlib.sha256(file_bytes).hexdigest()


# Global cache instance
_scan_cache = ScanCache()


def get_cache() -> ScanCache:
    return _scan_cache
