"""
Regex for RFC7230

These regex are directly derived from the collected ABNF in RFC7230:

  <https://httpwg.org/specs/rfc7838.html#alt-svc>

They should be processed with re.VERBOSE.
"""


from .rfc7230 import OWS, quoted_string, token, list_rule
from .rfc3986 import port, host as uri_host
from .rfc7234 import delta_seconds


# Alt-Svc       = clear / 1#alt-value
# clear         = %s"clear"; "clear", case-sensitive
# alt-value     = alternative *( OWS ";" OWS parameter )
# alternative   = protocol-id "=" alt-authority
# protocol-id   = token ; percent-encoded ALPN protocol name
# alt-authority = quoted-string ; containing [ uri-host ] ":" port
# parameter     = token "=" ( token / quoted-string )
# https://httpwg.org/specs/rfc7838.html#alt-svc
parameter = rf"{token} \= (?: {token} | {quoted_string})"
alt_authority = quoted_string
protocol_id = token
alternative = rf"{protocol_id} \= {alt_authority}"
alt_value = rf"{alternative} ({OWS} \; {OWS} {parameter})*"
clear = "clear"
Alt_Svc= rf"{clear} | {list_rule(alt_value, 1)}"
