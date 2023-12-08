"""
Regex for RFC5789

These regex are directly derived from the collected ABNF in RFC7231.

  <https://www.rfc-editor.org/rfc/rfc5789#section-3.1>

They should be processed with re.VERBOSE.
"""

from .rfc7230 import list_rule
from .rfc7231 import media_type

#    Accept-Patch = "Accept-Patch" ":" 1#media-type
Accept_Patch = list_rule(rf"(?: {media_type} )", 1)
