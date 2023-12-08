"""
This file helps validating string specified by ABNF using regex.
"""


import re
from typing import Union

from helpers.syntax.rfc5234 import DIGIT, DQUOTE
from .syntax.rfc3986 import URI, URI_reference, absolute_URI, relative_ref
from .syntax.rfc5646 import Language_Tag
from .syntax.rfc5789 import Accept_Patch
from .syntax.rfc6454 import serialized_origin, origin, origin_or_null
from .syntax.rfc7230 import (
    BWS,
    Upgrade,
    Transfer_Encoding,
    Connection,
    Content_Length,
    token,
    list_rule,
    quoted_string,
    OWS,
    obs_text,
)
from .syntax.rfc7231 import (
    IMF_fixdate,
    Server,
    obs_date,
    Vary,
    Retry_After,
    Location,
    HTTP_date,
    Accept,
    Accept_Encoding,
    Accept_Charset,
    Accept_Language,
    Allow,
    Content_Encoding,
    Content_Language,
    Content_Location,
    Content_Type,
    media_range,
)
from .syntax.rfc7233 import Range, Content_Range, Accept_Ranges
from .syntax.rfc7234 import Warning_, Pragma, Expires, Age, Cache_Control
from .syntax.rfc7235 import Proxy_Authorization, WWW_Authenticate
from .syntax.rfc7838 import Alt_Svc
from .syntax.rfc8941 import Accept_CH, sf_dictionary
from .syntax.csp import Content_Security_Policy
from .syntax.expect_ct import Expect_CT
from .syntax.rfc6797 import strict_transport_security
from .syntax.rfc5322 import domain


def check_regex(pattern: str, value: str) -> bool:
    """Check that the pattern matches the value. VERBOSE as the pattern contains WHITESPACE."""
    if re.match(pattern, value, re.VERBOSE):
        return True

    return False


def check_token(value: str) -> bool:
    return check_regex(f"^{token}$", value)


def check_uri(value: str) -> bool:
    return check_regex(f"^{URI}$", value)


def check_uri_reference(value: str) -> bool:
    return check_regex(f"^{URI_reference}$", value)


def check_absolute_uri(value: str) -> bool:
    return check_regex(f"^{absolute_URI}$", value)


def check_language_tag(value: str) -> bool:
    return check_regex(f"^{Language_Tag}$", value)


def check_content_language(value: str) -> bool:
    content_language = list_rule(rf"(?: {Language_Tag} )", 1)
    return check_regex(f"^{content_language}$", value)


def check_vary(value: str) -> bool:
    return check_regex(f"^{Vary}$", value)


def check_retry_after(value: str) -> bool:
    return check_regex(f"^{Retry_After}$", value)


def check_location(value: str) -> bool:
    return check_regex(f"^{Location}$", value)


def check_http_date(value: str) -> Union[bool, str]:
    """Senders must use IMF fixdate, but receivers must accept all three date formats
    Note this for every test that has to parse an HTTP date, instead of one main test for it
    https://www.rfc-editor.org/rfc/rfc9110.html#name-date-time-formats
    """
    if check_regex(f"^{IMF_fixdate}$", value):
        return True, "IMF fixdate"
    elif check_regex(f"^{obs_date}$", value):
        return True, "Obsolete date"
    else:
        return False, "No HTTP date"


def check_imf_fixdate(value: str) -> bool:
    return check_regex(f"^{IMF_fixdate}$", value)


def check_content_type(value: str) -> bool:
    return check_regex(f"^{Content_Type}$", value)


def check_content_location(value: str) -> bool:
    return check_regex(f"^{Content_Location}$", value)


def check_accept(value: str) -> bool:
    return check_regex(f"^{Accept}$", value)


def check_accept_charset(value: str) -> bool:
    return check_regex(f"^{Accept_Charset}$", value)


def check_accept_encoding(value: str) -> bool:
    return check_regex(f"^{Accept_Encoding}$", value)


def check_accept_language(value: str) -> bool:
    return check_regex(f"^{Accept_Language}$", value)


def check_allow(value: str) -> bool:
    return check_regex(f"^{Allow}$", value)


def check_content_encoding(value: str) -> bool:
    return check_regex(f"^{Content_Encoding}$", value)


def check_range(value: str) -> bool:
    return check_regex(f"^{Range}$", value)


def check_accept_ranges(value: str) -> bool:
    return check_regex(f"^{Accept_Ranges}$", value)


def check_content_range(value: str) -> bool:
    return check_regex(f"^{Content_Range}$", value)


def check_warning(value: str) -> bool:
    return check_regex(f"^{Warning_}$", value)


def check_www_authenticate(value: str) -> bool:
    return check_regex(f"^{WWW_Authenticate}$", value)


def check_transfer_encoding(value: str) -> bool:
    return check_regex(f"^{Transfer_Encoding}$", value)


def check_upgrade(value: str) -> bool:
    return check_regex(f"^{Upgrade}$", value)


def check_media_range(value: str) -> bool:
    return check_regex(f"^{media_range}$", value)


def check_csp(value: str) -> bool:
    return check_regex(f"^{Content_Security_Policy}$", value)


def check_csp_ro(value: str) -> bool:
    return check_csp(value)


def check_accept_patch(value: str) -> bool:
    return check_regex(f"^{Accept_Patch}$", value)


def check_accept_post(value: str) -> bool:
    accept_post = list_rule(rf"(?: {media_range} )", 1)
    return check_regex(f"^{accept_post}$", value)


def check_accept_ch(value: str) -> bool:
    return check_regex(f"^{Accept_CH}$", value)


def check_alt_svc(value: str) -> bool:
    return check_regex(f"^{Alt_Svc}$", value)


def check_expect_ct(value: str) -> bool:
    return check_regex(f"^{Expect_CT}$", value)


def check_serialized_origin(value: str) -> bool:
    return check_regex(f"^{serialized_origin}$", value)


def check_origin(value: str) -> bool:
    return check_regex(f"^{origin}$", value)


def check_sf_dictionary(value: str) -> bool:
    return check_regex(f"^{sf_dictionary}$", value)


def check_origin_or_null(value: str) -> bool:
    return check_regex(f"^{origin_or_null}$", value)


def check_token_list(value: str) -> bool:
    token_list = list_rule(rf"(?: {token} )", 1)
    return check_regex(f"^{token_list}$", value)


def check_cache_control(value: str) -> bool:
    cache_directive = rf"(?: {token} (?: = (?: {token} | {quoted_string} ) )? )"
    cache_control = list_rule(cache_directive, 1)
    return check_regex(f"^{cache_control}$", value)


def check_etag(value: str) -> bool:
    etagc = rf"(?: \x21 | [\x23-\x7E] | {obs_text} )"
    opaque_tag = rf"(?: {DQUOTE} {etagc}* {DQUOTE} )"
    weak = rf"(?: W/ )"
    entity_tag = rf"(?: {weak}? {opaque_tag} )"
    return check_regex(f"^{entity_tag}$", value)


def check_server(value: str) -> bool:
    return check_regex(f"^{Server}$", value)


def check_cookie(value: str) -> bool:
    # Current syntax (not official yet)
    # https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#name-syntax

    av_octet = rf"(?: [\x20-\x3A\x3C-\x7E] )"
    extension_av = rf"(?: {av_octet}* )"
    samesite_value = rf"(?: Strict | Lax | None )"
    samesite_av = rf"(?: SameSite {BWS} = {BWS} {samesite_value} )"
    httponly_av = rf"(?: HttpOnly )"
    secure_av = rf"(?: Secure )"
    path_value = rf"(?: {av_octet}* )"
    path_av = rf"(?: Path {BWS} = {BWS} {path_value} )"
    # This is more permissive than it should
    domain_value = domain
    domain_av = rf"(?: Domain {BWS} = {BWS} {domain_value} )"
    non_zero_digit = rf"(?: [\x31-\x39] )"
    max_age_av = rf"(?: Max-Age {BWS} = {BWS} {non_zero_digit} {DIGIT}* )"
    sane_cookie_date = IMF_fixdate
    expires_av = rf"(?: Expires {BWS} = {BWS} {sane_cookie_date} )"
    # Case-insensitive (i)
    cookie_av = rf"(?i: {expires_av} | {max_age_av} | {domain_av} | {path_av} | {secure_av} | {httponly_av} | {samesite_av} | {extension_av} )"
    cookie_octet = rf"(?: [\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E] )"
    cookie_value = (
        rf"(?: {cookie_octet}* | {DQUOTE} {cookie_octet}* {DQUOTE} )"  # Updated version
    )
    # cookie_value = rf"(?: {cookie_octet}* )"

    cookie_name = rf"(?: {cookie_octet}+ )"
    cookie_pair = rf"(?: {cookie_name} {BWS} = {BWS} {cookie_value} )"
    set_cookie_string = rf"(?: {BWS} {cookie_pair} (?: {BWS} ; {OWS} {cookie_av} )* )"
    set_cookie = set_cookie_string
    return check_regex(f"^{set_cookie}$", value)


def check_proxy_authorization(value: str) -> bool:
    return check_regex(f"^{Proxy_Authorization}$", value)


def check_sts(value: str) -> bool:
    return check_regex(f"^{strict_transport_security}$", value)


def check_content_disposition(value: str) -> bool:
    # https://www.rfc-editor.org/rfc/rfc6266.html#section-4.1
    # No parsing for inline, filename, ... as disp-ext-type and disp-ext-parm can be token
    val = rf"(?: {token} | {quoted_string} )"
    disposition_parm = rf"(?: {token} \= {val} )"
    cd = rf"(?: {token} (?: {OWS} ; {OWS} {disposition_parm} )* )"
    return check_regex(f"^{cd}$", value)
