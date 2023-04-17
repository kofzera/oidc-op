from oidcmsg.oauth2 import TokenIntrospectionResponse
from oidcmsg.message import SINGLE_OPTIONAL_STRING, SINGLE_REQUIRED_INT
from oidcmsg.oauth2 import TokenIntrospectionRequest

from oidcop.token import UnknownToken, WrongTokenClass


class UpdatedTokenIntrospectionResponse(TokenIntrospectionResponse):
    c_param = TokenIntrospectionResponse.c_param.copy()
    c_param.update({"auth_time": SINGLE_REQUIRED_INT, "acr": SINGLE_OPTIONAL_STRING})


def pre_construct(response_args, request, endpoint_context, **kwargs):
    _introspect_request = TokenIntrospectionRequest(**request)
    request_token = _introspect_request["token"]
    try:
        _session_info = endpoint_context.session_manager.get_session_info_by_token(
            request_token, grant=True
        )
    except (UnknownToken, WrongTokenClass):
        return response_args
    grant = _session_info["grant"]
    response_args["auth_time"] = grant.authentication_event["authn_time"]
    response_args["acr"] = grant.authentication_event["authn_info"]
    return response_args


def add_support(endpoint, **kwargs):
    _introspection_endp = endpoint["introspection"]
    _introspection_endp.pre_construct.append(pre_construct)