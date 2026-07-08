import http.client
import json

from pathlib import Path
from typing import Any, Optional, Dict, cast
from urllib.error import URLError
from urllib.request import urlopen

import diskcache

_SIGMAHQ_PROVIDER_URL = (
    "https://raw.githubusercontent.com/SigmaHQ/pySigma-validators-sigmaHQ/refs/heads/main/"
    "tools/sigmahq_windows_provider.json"
)

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "pysigma" / "sigmahq"

_cache: Optional[diskcache.Cache] = None
_custom_url: Optional[str] = None
_custom_cache_dir: Optional[Path] = None


def _get_cache() -> diskcache.Cache:
    global _cache
    if _cache is None:
        cache_dir = _custom_cache_dir if _custom_cache_dir is not None else _DEFAULT_CACHE_DIR
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache = diskcache.Cache(str(cache_dir))
    return _cache


def _load_sigmahq_json() -> Dict[str, Any]:
    cache = _get_cache()
    cache_key = f"sigmahq_provider_{_custom_url or 'default'}"

    cached_data = cache.get(cache_key)
    if cached_data is not None:
        return cast(Dict[str, Any], cached_data)

    url = _custom_url if _custom_url is not None else _SIGMAHQ_PROVIDER_URL

    try:
        if not url.startswith(("http://", "https://")):
            with open(url, "r", encoding="utf-8") as f:
                json_data = json.load(f)
        else:
            with urlopen(url, timeout=30) as response:
                json_data = json.load(response)
    except (URLError, json.JSONDecodeError, OSError, IOError, http.client.HTTPException) as e:
        raise RuntimeError(f"Failed to load data: {e}") from e

    sigmahq_provider_version = json_data.get("version", "unknown")
    sigmahq_provider_name = json_data.get("category_provider_name", {})

    result = {
        "sigmahq_provider_version": sigmahq_provider_version,
        "sigmahq_provider_name": sigmahq_provider_name,
    }

    cache.set(cache_key, result)

    return result


def _get_cached_data() -> Dict[str, Any]:
    return _load_sigmahq_json()


def __getattr__(name: str) -> Any:
    if name.startswith("sigmahq_provider_"):
        data = _get_cached_data()
        if name in data:
            return data[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def clear_cache() -> None:
    cache = _get_cache()
    cache.clear()


def set_url(url: str) -> None:
    global _custom_url, _cache
    _custom_url = url
    clear_cache()
    _cache = None


def set_cache_dir(cache_dir: str) -> None:
    global _cache, _custom_cache_dir
    _custom_cache_dir = Path(cache_dir)
    if _cache is not None:
        _cache.close()
        _cache = None
