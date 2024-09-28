import time
from typing import Optional
from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp

class JWKSetCache:

    def __init__(self, lifespan: int) -> None:
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan