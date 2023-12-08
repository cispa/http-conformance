"""
Regex for Expect-CT Extension for HTTP

  <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-expect-ct-08#section-2.1>

They should be processed with re.VERBOSE.
"""
from .rfc7230 import quoted_string, token, list_rule

   # Expect-CT           = 1#expect-ct-directive
   # expect-ct-directive = directive-name [ "=" directive-value ]
   # directive-name      = token
   # directive-value     = token / quoted-string
# https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-expect-ct-08#section-2.1
directive_value = rf"(?: {token} | {quoted_string})"
directive_name = token
expect_ct_directive = rf"(?: {directive_name} (?: \= {directive_value})? )"
Expect_CT = list_rule(expect_ct_directive, 1)
