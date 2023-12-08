"""
Regex for RFC8941

  <https://www.rfc-editor.org/rfc/rfc8941>

They should be processed with re.VERBOSE.
"""

from .rfc7230 import OWS, tchar
from .rfc5234 import DIGIT, DQUOTE, ALPHA, SP

# sf-integer = ["-"] 1*15DIGIT
# https://www.rfc-editor.org/rfc/rfc8941#integer
sf_integer = rf"(?: -? {DIGIT}{{1,15}})"

# sf-decimal  = ["-"] 1*12DIGIT "." 1*3DIGIT
# https://www.rfc-editor.org/rfc/rfc8941#decimal
sf_decimal = rf"(?: -? {DIGIT}{{1,12}} \. {DIGIT}{{1,3}})"

# sf-string = DQUOTE *chr DQUOTE
# chr       = unescaped / escaped
# unescaped = %x20-21 / %x23-5B / %x5D-7E
# escaped   = "\" ( DQUOTE / "\" )
# https://www.rfc-editor.org/rfc/rfc8941#string
escaped = rf"(?: \\ (?: {DQUOTE} | \\ ) )"
unescaped = rf"(?: [\x20-\x21\x23-\x5B\x5D-\x7E] )"
chr = rf"(?: {unescaped} | {escaped} )"
sf_string = rf"(?: {DQUOTE} {chr}* {DQUOTE} )"

# sf-token = ( ALPHA / "*" ) *( tchar / ":" / "/" )
# https://www.rfc-editor.org/rfc/rfc8941#token
sf_token = rf"(?: (?: {ALPHA} | \* ) (?: {tchar} | \: | \/ )* )"

# sf-binary = ":" *(base64) ":"
# base64    = ALPHA / DIGIT / "+" / "/" / "="
# https://www.rfc-editor.org/rfc/rfc8941#binary
base64 = rf"(?: {ALPHA} | {DIGIT} | \+ | \/ | \= )"
sf_binary = rf"(?: \: {base64}* \: )"

# sf-boolean = "?" boolean
# boolean    = "0" / "1"
# https://www.rfc-editor.org/rfc/rfc8941#boolean
boolean = rf"(?: [01] )"
sf_boolean = rf"(?: \? {boolean} )"


# bare-item = sf-integer / sf-decimal / sf-string / sf-token
#             / sf-binary / sf-boolean
# https://www.rfc-editor.org/rfc/rfc8941#item
bare_item = rf"(?: {sf_integer} | {sf_decimal} | {sf_string} | {sf_token} | {sf_binary} | {sf_boolean} )"


# parameters    = *( ";" *SP parameter )
# parameter     = param-key [ "=" param-value ]
# param-key     = key
# key           = ( lcalpha / "*" )
#                 *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
# lcalpha       = %x61-7A ; a-z
# param-value   = bare-item
# https://www.rfc-editor.org/rfc/rfc8941#param
param_value = bare_item
lcalpha = rf"(?: [a-z] )"
key = rf"(?: (?: {lcalpha} | \* ) (?: {lcalpha} | {DIGIT} | \_ | \- | \. | \*) * )"
param_key = key
parameter = rf"(?: {param_key} (?: \= {param_value} )? )"
parameters = rf"(?: (?: \; {SP}* {parameter} )* )"


# sf-item   = bare-item parameters
# https://www.rfc-editor.org/rfc/rfc8941#item
sf_item = rf"(?: {bare_item} {parameters} )"


# inner-list    = "(" *SP [ sf-item *( 1*SP sf-item ) *SP ] ")"
#                 parameters
# https://www.rfc-editor.org/rfc/rfc8941#inner-list
inner_list = rf"(?: \( {SP}* (?: {sf_item} (?: {SP}+ {sf_item} )* {SP}* )? \) {parameters} )"


# sf-list       = list-member *( OWS "," OWS list-member )
# list-member   = sf-item / inner-list
# https://www.rfc-editor.org/rfc/rfc8941#section-3.1
list_member = rf"(?: {sf_item} | {inner_list} )"
sf_list = rf"(?: {list_member} (?: {OWS} \, {OWS} {list_member} )* )"

# sf-dictionary  = dict-member *( OWS "," OWS dict-member )
# dict-member    = member-key ( parameters / ( "=" member-value ))
# member-key     = key
# member-value   = sf-item / inner-list

member_value = rf"(?: {sf_item} | {inner_list} )"
member_key = key
dict_member = rf"(?: {member_key} (?: {parameters} | (?: = {member_value} ) ) )"
sf_dictionary = rf"(?: {dict_member} (?: {OWS} , {OWS} {dict_member} )* )"


### Usage below

# Accept-CH = sf-list
Accept_CH = sf_list

