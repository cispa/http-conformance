#!/usr/bin/env python
"""
Regex for URIs

These regex are directly derived from the collected ABNF in RFC3986:

  https://www.rfc-editor.org/rfc/rfc6454#page-10

They should be processed with re.VERBOSE.
"""

# pylint: disable=invalid-name

from .rfc3986 import scheme, host, port
from .rfc5234 import SP
from .rfc7230 import OWS

# origin              = "Origin:" OWS origin-list-or-null OWS
# origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list
# origin-list         = serialized-origin *( SP serialized-origin )
# serialized-origin   = scheme "://" host [ ":" port ]
#                     ; <scheme>, <host>, <port> from RFC 3986
serialized_origin = rf"(?: {scheme} \:\/\/ {host} (?: \: {port} )? )"
origin_list = rf"(?: {serialized_origin} (?: {SP} {serialized_origin})* )"
origin_list_or_null = rf"(?: null | {origin_list} )"
# Origin Header
origin = rf"(?: {OWS} {origin_list_or_null} {OWS} )"

# Origin or null
origin_or_null = rf"(?: null | {serialized_origin} )"

