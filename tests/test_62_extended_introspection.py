import os
import json

import pytest
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.time_util import utc_time_sans_frac

from oidcop import user_info
from oidcop.authn_event import create_authn_event
from oidcop.client_authn import verify_client
from oidcop.configure import OPConfiguration
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.introspection import Introspection
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "add_on": {
                "extra_args": {
                    "function": "oidcop.oauth2.add_on.extended_introspection_response.add_support",
                    "kwargs": {
                    }
                },
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
                },
                "id_token": {
                    "class": "oidcop.token.id_token.IDToken",
                    "kwargs": {
                        "base_claims": {
                            "email": {"essential": True},
                            "email_verified": {"essential": True},
                        }
                    },
                },
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "introspection": {
                    "path": "{}/intro",
                    "class": Introspection,
                    "kwargs": {
                        "client_authn_method": ["client_secret_post"],
                        "enable_claims_per_client": False,
                    },
                },
                "token": {
                    "path": "{}/token",
                    "class": Token,
                    "kwargs": {}},
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": "users.json"},
            },
        }
        server = Server(OPConfiguration(conf, base_path=BASEDIR), keyjar=KEYJAR)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint_context.keyjar.import_jwks_as_json(
            self.endpoint_context.keyjar.export_jwks_as_json(private=True), self.endpoint_context.issuer,
        )
        self.endpoint = server.server_get("endpoint", "introspection")
        self.token_endpoint = server.server_get("endpoint", "token")
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = "diana"

    def test_process_request(self):
        _acr = "https://refeds.org/profile/mfa"
        _context = self.endpoint.server_get("endpoint_context")
        session_id = self._create_session(AUTH_REQ, authn_info=_acr)
        grant = self.token_endpoint.server_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)
        _req = self.endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.endpoint.process_request(_req)
        _resp_after = self.endpoint.do_response(request=_req, **_resp)
        _parsed_resp_after = json.loads(_resp_after["response"])
        assert "acr" in _parsed_resp_after
        assert _parsed_resp_after["acr"] == _acr
        assert "auth_time" in _parsed_resp_after


    def _create_session(self, auth_req, sub_type="public", sector_identifier="", authn_info=None):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id, authn_info=authn_info)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_token(self, token_class, grant, session_id, based_on=None, **kwargs):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.token_endpoint.server_get("endpoint_context"),
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )
