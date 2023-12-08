"""
Regex for STS

These regex are directly derived from the core ABNF in RFC6797:

  https://www.rfc-editor.org/rfc/rfc6797#section-6.1

They should be processed with re.VERBOSE.
"""
from .rfc7230 import list_rule, OWS, quoted_string, token

# directive-value           = token | quoted-string
directive_value = rf"(?: {token} | {quoted_string} )"

# directive-name            = token
directive_name = token

# directive                 = directive-name [ "=" directive-value ]
directive = rf"(?: {directive_name} (?: = {directive_value} )? )"

# Strict-Transport-Security = "Strict-Transport-Security" ":"
#                                 [ directive ]  *( ";" [ directive ] )
strict_transport_security = rf"(?: {directive}? (?: {OWS} ; {OWS} {directive}? )* )"