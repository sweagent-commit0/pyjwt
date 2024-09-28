import json
import urllib.request
from functools import lru_cache
from ssl import SSLContext
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache

class PyJWKClient:

    def __init__(self, uri: str, cache_keys: bool=False, max_cached_keys: int=16, cache_jwk_set: bool=True, lifespan: int=300, headers: Optional[Dict[str, Any]]=None, timeout: int=30, ssl_context: Optional[SSLContext]=None):
        if headers is None:
            headers = {}
        self.uri = uri
        self.jwk_set_cache: Optional[JWKSetCache] = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cache_jwk_set:
            if lifespan <= 0:
                raise PyJWKClientError(f'Lifespan must be greater than 0, the input is "{lifespan}"')
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None
        if cache_keys:
            self.get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)