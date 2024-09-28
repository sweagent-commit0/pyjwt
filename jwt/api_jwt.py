from __future__ import annotations
import json
import warnings
from calendar import timegm
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from . import api_jws
from .exceptions import DecodeError, ExpiredSignatureError, ImmatureSignatureError, InvalidAudienceError, InvalidIssuedAtError, InvalidIssuerError, MissingRequiredClaimError
from .warnings import RemovedInPyjwt3Warning
if TYPE_CHECKING:
    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys

class PyJWT:

    def __init__(self, options: dict[str, Any] | None=None) -> None:
        if options is None:
            options = {}
        self.options: dict[str, Any] = {**self._get_default_options(), **options}

    def _encode_payload(self, payload: dict[str, Any], headers: dict[str, Any] | None=None, json_encoder: type[json.JSONEncoder] | None=None) -> bytes:
        """
        Encode a given payload to the bytes to be signed.

        This method is intended to be overridden by subclasses that need to
        encode the payload in a different way, e.g. compress the payload.
        """
        pass

    def _decode_payload(self, decoded: dict[str, Any]) -> Any:
        """
        Decode the payload from a JWS dictionary (payload, signature, header).

        This method is intended to be overridden by subclasses that need to
        decode the payload in a different way, e.g. decompress compressed
        payloads.
        """
        pass
_jwt_global_obj = PyJWT()
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode