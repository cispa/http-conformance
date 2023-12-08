"""
Regex for Content Security Policy Level 3

  <https://w3c.github.io/webappsec-csp/#grammardef-serialized-policy>

They should be processed with re.VERBOSE.
"""

from .rfc5234 import ALPHA, DIGIT
from .rfc7230 import list_rule

SPEC_URL = "https://w3c.github.io/webappsec-csp/#grammardef-serialized-policy"


# optional-ascii-whitespace = *( %x09 / %x0A / %x0C / %x0D / %x20 )
# required-ascii-whitespace = 1*( %x09 / %x0A / %x0C / %x0D / %x20 )
# https://w3c.github.io/webappsec-csp/#grammardef-optional-ascii-whitespace
optional_ascii_whitespace = rf"(?: (?: \x09 | \x0A | \x0C | \x0D | \x20 )* )"
required_ascii_whitespace = rf"(?: (?: \x09 | \x0A | \x0C | \x0D | \x20 )+ )"

# directive-name       = 1*( ALPHA / DIGIT / "-" )
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-directive
directive_name = rf"(?: (?: {ALPHA}| {DIGIT} | \- )+ )"

# directive-value      = *( required-ascii-whitespace / ( %x21-%x2B / %x2D-%x3A / %x3C-%x7E ) )
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-directive
directive_value = rf"(?: (?: {required_ascii_whitespace} | [\x21-\x2B\x2D-\x3A\x3C-\x7E] )* )"

# serialized-directive = directive-name [ required-ascii-whitespace directive-value ]
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-directive
serialized_directive = rf"(?: {directive_name} (?: {required_ascii_whitespace} {directive_value} )? )"

# serialized-policy = serialized-directive *( optional-ascii-whitespace ";" [ optional-ascii-whitespace serialized-directive ] )
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-policy
serialized_policy = rf"(?: {serialized_directive} (?: {optional_ascii_whitespace} \; (?: {optional_ascii_whitespace} {serialized_directive} )? )* )"

# Content-Security-Policy = 1#serialized-policy
# https://w3c.github.io/webappsec-csp/#csp-header
Content_Security_Policy = list_rule(serialized_policy, 1)
