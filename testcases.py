"""
HTTP Server RFC Compliance Tests
"""
import sys
import re
import dpkt
from mitmproxy import http, net
from helpers.db_util import (
    Violation,
    Activity,
    Level,
    ReqResp,
    ProbeTest,
    DirectTest,
    RetroTest,
    Url,
)
from helpers.direct_util import build_request, one_req, get_codes
from helpers.util import parse_headers
from helpers import syntax_validation as checks


class continue_before_upgrade:
    title = """
    If a client sends both Upgrade and Expect 100-continue, a server must send a response with 100 first and then one with code 101
    """
    description = """
    If a server receives both an Upgrade and an Expect header field with the "100-continue" expectation (Section 10.1.1), the server MUST send a 100 (Continue) response before sending a 101 (Switching Protocols) response.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-upgrade"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send both upgrade and expect 100-continue (apache only send 100 if request advertises content!)"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        req = build_request(
            url.host,
            url.port,
            request_target=url.path,
            connection_header=b"Connection: upgrade\r\n",
            additional_headers=b"Upgrade: https\r\nExpect: 100-continue\r\n",
        )
        violation = Violation.INAPPLICABLE
        extra = ""
        codes = get_codes(one_req(url, dt, req))
        if "101" in codes:
            if "100" in codes:
                if codes.index("100") < codes.index("101"):
                    violation = Violation.VALID
                else:
                    violation = Violation.INVALID
                    extra += "100 not before 101"
            else:
                violation = Violation.INVALID
                extra += "Upgrade only (no 100)"
        elif "100" in codes:
            extra += "100 without upgrade"
        else:
            extra += "No upgrade no 100"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Send 100 first and then 101"""
        response.writer.write_status(100)
        response.writer.end_headers()
        response.writer.write_status(101)
        response.writer.write_header("Connection", "upgrade")
        response.writer.write_header("Upgrade", "https")
        response.writer.end_headers()

    def invalid(self, request, response):
        """Only sends 101 (Problem: does not work correctly as WPTserve sends an automatic response to Expect: 100-Continue)"""
        response.writer.write_status(101)
        response.writer.write_header("Connection", "upgrade")
        response.writer.write_header("Upgrade", "https")
        response.writer.end_headers()


class reject_fields_contaning_cr_lf_nul:
    title = """
    Reject messages with field values containing CR, LF or NUL (or replace with SP)
    """
    description = """
    Field values containing CR, LF, or NUL characters are invalid and dangerous, due to the varying ways that implementations might parse and interpret those characters; a recipient of CR, LF, or NUL within a field value MUST either reject the message or replace each of those characters with SP before further processing or forwarding of that message.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-field-values"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send request with NUL, CR, LF in field value. (Problem: we cannot know whether they are replaced with SP? Could only check this for proxies?)"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        violation = Violation.VALID
        extra = ""
        for inv in [b"\x00", b"\r", b"\n"]:
            req = build_request(
                url.host,
                url.port,
                request_target=url.path,
                additional_headers=b"Invalid: a" + inv + b"\r\n",
            )
            code = get_codes(one_req(url, dt, req))[0]
            if "invalid response" in repr(code):
                violation = Violation.UNCLEAR
            elif code != "400":
                extra += f"{inv} results in {code}! "
                violation = Violation.INVALID
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Ignore requests with CR/LF/NUL in field value. (ignore all)"""
        return 400, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Do not ignore requests with CR/LF/NUL in field value."""
        return 200, [], "<div>ABC</div>"


class code_400_after_bad_host_request:
    title = """
    Reply with 400 to requests with bad hosts
    """
    description = """
    A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-request-target"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send invalid host requests (no host, 2 hosts, invalid host) and check for 400 (http/1.1)"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        for host_header, desc in [
            (b"", "no host"),
            (
                2
                * (
                    b"Host: "
                    + url.host.encode("utf-8")
                    + b":"
                    + str(url.port).encode("utf-8")
                    + b"\r\n"
                ),
                "2 hosts",
            ),
            (b"Host: abc\r\n", "invalid host"),
        ]:
            req = build_request(
                url.host,
                url.port,
                request_target=url.path,
                host_header=host_header,
                additional_headers=b"inv: a\r\ninv: ab\r\n",
            )
            code = get_codes(one_req(url, dt, req))[0]
            if "invalid response" in repr(code):
                violation = Violation.UNCLEAR
            elif code != "400":
                extra += f"{desc} results in {code}! "
                violation = Violation.INVALID
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """400 for no host, duplicate host, invalid host"""
        host_headers = request.headers.get_list("host", default=[])
        if len(host_headers) == 1 and host_headers[0] == b"leaking.via:5001":
            return 200, [], "<div>ABC</div>"
        return 400, [], ""

    def invalid(self, request, response):
        """Never 400"""
        return 200, [], "<div>ABC</div>"


class code_501_unknown_methods:
    title = """
    Servers should reply with code 501 for unknown request methods
    """
    description = """
    An origin server that receives a request method that is unrecognized or not implemented SHOULD respond with the 501 (Not Implemented) status code. 
    """
    type = Level.RECOMMENDATION
    category = "HTTP Methods"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-overview"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Probe statuscode with invalid HTTP method"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        for method in [b"ABC"]:
            req = build_request(
                url.host, url.port, method=method, request_target=url.path
            )
            code = get_codes(one_req(url, dt, req))[0]
            if "invalid response" in repr(code):
                violation = Violation.UNCLEAR
            elif code != "501":
                extra += f"{method} results in {code}! "
                violation = Violation.INVALID
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Return 200 for recognized HTTP method else 501"""
        code = 501
        if request.method in [
            "GET",
            "HEAD",
            "POST",
            "TRACE",
            "PUT",
            "PATCH",
            "OPTIONS",
            "DELETE",
            "CONNECT",
        ]:
            code = 200
        return code, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Always return 200"""
        return 200, [], "<div>ABC</div>"


class code_405_blocked_methods:
    title = """
    Servers should reply with code 405 when the request method is not allowed for the target resource
    """
    description = """
    An origin server that receives a request method that is recognized and implemented, but not allowed for the target resource, SHOULD respond with the 405 (Method Not Allowed) status code.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Methods"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-overview"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Probe statuscode with some HTTP methods (e.g., CONNECT should probably be disallowed)"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        for method in [b"TRACE", b"CONNECT"]:
            req = build_request(
                url.host, url.port, method=method, request_target=url.path
            )
            code = get_codes(one_req(url, dt, req))[0]
            if "invalid response" in repr(code):
                if violation == Violation.VALID:
                    violation = Violation.UNCLEAR
                extra += f"{method} results in invalid response! "
            elif code != "405":
                extra += f"{method} results in {code}! "
                violation = Violation.INVALID
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Return 200 for GET/HEAD HTTP method else 405 (Problem: Connect does not reach here)"""
        code = 405
        if request.method in ["GET", "HEAD"]:
            code = 200
        return code, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Always return 200"""
        return 200, [], "<div>ABC</div>"


class content_head_request:
    title = """
    No Message Body in Head
    """
    description = """
    The HEAD method is identical to GET except that the server MUST NOT send content in the response.
    """
    type = Level.REQUIREMENT
    category = "HTTP Methods"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-head"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send HEAD request and check if there is data after the headers."""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        req = build_request(url.host, url.port, method=b"HEAD", request_target=url.path)
        resp = one_req(url, dt, req, head_response=True)[0][0]
        if type(resp) == dpkt.UnpackError:
            violation = Violation.UNCLEAR
            extra = f"{resp}"
        elif resp.data != b"":
            violation = Violation.INVALID
            extra = f"Additional data to head response: {resp.data}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Does not send body for head requests"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Sends body for head requests"""
        response.send_body_for_head_request = True
        return 200, [], "<div>ABC</div>"


class allow_crlf_start:
    title = """
    One CRLF infront of the request line should be allowed.
    """
    description = """
    In the interest of robustness, a server that is expecting to receive and parse a request-line SHOULD ignore at least one empty line (CRLF) received prior to the request-line.
    """
    type = Level.RECOMMENDATION
    category = "HTTP/1.1"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-message-parsing"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send request with CRLF before start."""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        req = build_request(url.host, url.port, request_target=url.path)
        req.req_raw = b"\r\n" + req.req_raw
        resp = one_req(url, dt, req)[0][0]
        if type(resp) == dpkt.http.Response:
            if not (resp.status[0] in ["2", "3"] or resp.status == "404"):
                violation = Violation.INVALID
                extra = f"Status = {resp.status}"
        else:
            violation = Violation.INVALID
            extra = f"{resp}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Allow all messages (Problem: wptserve/python closes connection directly; after first CRLF line)"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Reject all messages"""
        return 400, [], "<div>ABC</div>"


class reject_msgs_with_whitespace_between_startline_and_first_header_field:
    title = """
    Reject messages with whitespace between start-line and first header-field
    """
    description = """
    A recipient that receives whitespace between the start-line and the first header field MUST either reject the message as invalid or consume each whitespace-preceded line without further processing of it (i.e., ignore the entire line, along with any subsequent lines preceded by whitespace, until a properly formed header field is received or the header section is terminated). 
    """
    type = Level.REQUIREMENT
    category = "HTTP/1.1"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-message-parsing"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send invalid request: whitespace in front of (all) headers."""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        req = build_request(url.host, url.port, request_target=url.path)
        req.req_raw = b"\r\n ".join(req.req_raw.split(b"\r\n")[:-2]) + b"\r\n\r\n"
        code = get_codes(one_req(url, dt, req))[0]
        if "invalid response" in repr(code):
            violation = Violation.UNCLEAR
        elif code != "400":
            violation = Violation.INVALID
            extra = f"Status: {code}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Always reject (reject messages with whitespace between start-line and first-header)"""
        return 400, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Always return 200"""
        return 200, [], "<div>ABC</div>"


class code_400_if_msg_with_whitespace_between_header_field_and_colon:
    title = """
    Server must reject (400 status code) any message with a whitespace between header field and colon
    (Problem: for real websites we cannot really distinguish between whether a proxy correctly removed the whitespaces or if a server incorrectly did not reject the message)
    (Add a testcase for obs-line-folding: https://www.rfc-editor.org/rfc/rfc9112#name-obsolete-line-folding)
    """
    description = """
    A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon.
    """
    type = Level.REQUIREMENT
    category = "HTTP/1.1"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-field-line-parsing"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT

    def test(self, url: Url) -> DirectTest:
        """Send invalid request (whitespace between header and colon)"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        req = build_request(
            url.host,
            url.port,
            request_target=url.path,
            additional_headers=b"Space : Ohno\r\n",
        )
        code = get_codes(one_req(url, dt, req))[0]
        if "invalid response" in repr(code):
            violation = Violation.UNCLEAR
        elif code != "400":
            violation = Violation.INVALID
            extra = f"Status: {code}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Reject messages with whitespace between header and colon (reject everything)"""
        return 400, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Always return the same response"""
        return 200, [], "<div>ABC</div>"


class content_length_2XX_connect:
    title = """
    No content-length header allowed for 2XX responses to connect
    """
    description = """
    A server MUST NOT send a Content-Length header field in any 2xx (Successful) response to a CONNECT request (Section 9.3.6)
    (Request does not include a cache-control header, but CONNECT is not cacheable)
    (Add additional test invalid port in connect? (A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.))
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-content-length"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT_BASE

    def test(self, url: Url) -> DirectTest:
        """Send connect requests and observe behavior."""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        r_host = url.host.encode("utf-8") + b":" + str(url.port).encode("utf-8")
        req = build_request(
            url.host,
            url.port,
            request_line=b"CONNECT " + r_host + b" HTTP/1.1\r\n",
            headers=b"Host: " + r_host + b"\r\n\r\n",
        )
        resp = one_req(url, dt, req)[0][0]
        if type(resp) == dpkt.http.Response:
            if (
                resp.status == "200"
                and resp.headers.get("content-length", None) != None
            ):
                violation = Violation.INVALID
        else:
            violation = Violation.INAPPLICABLE
            extra = f"{resp}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Do not return CL for connect requests"""
        return 200, [], "<div>abc</div>"

    def invalid(self, request, response):
        """Return content-length for connect requests (Problem: CONNECT does not reach here!)"""
        return 200, [("Content-Length", 14)], "<div>abc</div>"


class transfer_encoding_2XX_connect:
    title = """
    A server MUST NOT send a Transfer-Encoding header field in any 2xx (Successful) response to a CONNECT request (Section 9.3.6 of [HTTP])
    """
    description = """
    A server MUST NOT send a Transfer-Encoding header field in any 2xx (Successful) response to a CONNECT request (Section 9.3.6 of [HTTP])
    (Request does not include a cache-control header, but CONNECT is not cacheable)
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9112#field.transfer-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.DIRECT_BASE

    def test(self, url: Url) -> DirectTest:
        """Send connect and observe TE"""
        dt = DirectTest.create(url=url, name=self.name, type=self.type)
        extra = ""
        violation = Violation.VALID
        r_host = url.host.encode("utf-8") + b":" + str(url.port).encode("utf-8")
        req = build_request(
            url.host,
            url.port,
            request_line=b"CONNECT " + r_host + b" HTTP/1.1\r\n",
            headers=b"Host: " + r_host + b"\r\n\r\n",
        )
        resp = one_req(url, dt, req)[0][0]
        if type(resp) == dpkt.http.Response:
            if (
                resp.status == "200"
                and resp.headers.get("transfer-encoding", None) != None
            ):
                violation = Violation.INVALID
        else:
            violation = Violation.INAPPLICABLE
            extra = f"{resp}"
        dt.violation = violation
        dt.extra = extra
        dt.save()
        return dt

    def valid(self, request, response):
        """Do not send TE"""
        return 200, [], "<div>abc</div>"

    def invalid(self, request, response):
        """Send TE (problem: connect does not reach here)"""
        return 200, [("Transfer-Encoding", "gzip")], "<div>abc</div>"


class response_directive_no_cache:
    title = """
    No token form in no-cache directive
    """
    description = """
    This directive uses the quoted-string form of the argument syntax. A sender SHOULD NOT generate the token form (even if quoting appears not to be needed for single-entry lists).
    """
    type = Level.RECOMMENDATION
    category = "Cache-Control"
    source = "https://www.rfc-editor.org/rfc/rfc9111#name-no-cache-2"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check that char after no-cache=? is DQUOTE (assumes quote is closed correctly)"""
        cc = flow.response.headers.get("Cache-Control", "")
        next_chars = re.findall("no-cache=(.)", cc)
        if not next_chars:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        for next_char in next_chars:
            if next_char != '"':
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid no-cache directive (CC)"""
        return 200, [("Cache-Control", 'no-cache="age"')], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid no-cache directive (CC)"""
        return 200, [("Cache-Control", "no-cache=age")], "<div>ABC</div>"


class response_directive_private:
    title = """
    No token form in private directive
    """
    description = """
    This directive uses the quoted-string form of the argument syntax. A sender SHOULD NOT generate the token form (even if quoting appears not to be needed for single-entry lists).
    """
    type = Level.RECOMMENDATION
    category = "Cache-Control"
    source = "https://www.rfc-editor.org/rfc/rfc9111#name-private"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check that char after private=? is DQUOTE"""
        cc = flow.response.headers.get("Cache-Control", "")
        next_chars = re.findall("private=(.)", cc)
        if not next_chars:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        for next_char in next_chars:
            if next_char != '"':
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid private directive (CC)"""
        return 200, [("Cache-Control", 'private="x-frame-options"')], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid private directive (CC)"""
        return 200, [("Cache-Control", "private=x-frame-options")], "<div>ABC</div>"


class response_directive_max_age:
    title = """
    No Quoted String in Max Age Directive
    """
    description = """
    This directive uses the token form of the argument syntax: e.g., 'max-age=5' not 'max-age="5"'. A sender MUST NOT generate the quoted-string form.
    """
    type = Level.REQUIREMENT
    category = "Cache-Control"
    source = "https://www.rfc-editor.org/rfc/rfc9111#name-max-age-2"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check that char after max-age=? is  not DQUOTE"""
        cc = flow.response.headers.get("Cache-Control", "")
        next_chars = re.findall("max-age=(.)", cc)
        if not next_chars:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        for next_char in next_chars:
            if next_char == '"':
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid max-age directive (CC)"""
        return 200, [("Cache-Control", "max-age=5")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid max-age directive (CC)"""
        return 200, [("Cache-Control", 'max-age="5"')], "<div>ABC</div>"


class response_directive_s_maxage:
    title = """
    No Quoted String in S-Maxage directive
    """
    description = """
    This directive uses the token form of the argument syntax: e.g., 's-maxage=10' not 's-maxage="10"'. A sender MUST NOT generate the quoted-string form.
    """
    type = Level.REQUIREMENT
    category = "Cache-Control"
    source = "https://www.rfc-editor.org/rfc/rfc9111#name-s-maxage"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check that char after s-maxage=? is not DQUOTE"""
        cc = flow.response.headers.get("Cache-Control", "")
        next_chars = re.findall("s-maxage=(.)", cc)
        if not next_chars:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        for next_char in next_chars:
            if next_char == '"':
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid s-maxage (CC)"""
        return 200, [("Cache-Control", "s-maxage=10")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid s-maxage (CC)"""
        return 200, [("Cache-Control", 's-maxage="10"')], "<div>ABC</div>"


class duplicate_fields:
    title = """
    Fields (headers + trailers) are not allowed to occur several times unless their definition allows it
    """
    description = """
    A sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that fields definition allows multiple field line values to be recombined as a comma-separated list (i.e., at least one alternative of the fields definition allows a comma-separated list, such as an ABNF rule of #(values) defined in Section 5.6.1).
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-field-order"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        allow_multiple_headers = {
            b"set-cookie",
            b"content-language",
            b"vary",
            b"server-timing",
            b"link",
            b"accept-ch",
            b"cache-control",
            b"p3p",
            b"content-security-policy",
            b"connection",
            b"referrer-policy",
            b"via",
            b"alt-svc",
            b"content-security-policy-report-only",
            b"accept-ranges",
            b"allow",
            b"www-authenticate",
            b"pragma",
        }
        allow_multiple_headers_custom = {
            b"x-cache-lookup",
            b"eagleeye-traceid",
            b"x-feserver",
            b"fss-proxy",
            b"x-request-id",
            b"x-cache",
            b"x-upstream-address",
            b"lb",
            b"x-amz-cf-pop",
            b"x-served-by",
            b"x-edgeconnect-midmile-rtt",
            b"x-edgeconnect-origin-mex-latency",
            b"x-xss-protection",
            b"x-powered-by",
            b"x-backendhttpstatus",
            b"x-node",
            b"traceparent",
            b"tracestate",
            b"x-parent-response-time",
            b"x-grn",
            b"x-origin-cc",
            b"x-origin-ttl",
            b"x-ua-compatible",
            b"x-goog-hash",
            b"akamai-true-ttl",
            b"x-air-pt",
            b"x-amz-id-2",
            b"x-amz-request-id",
            b"x-vhost",
            b"x-rid",
            b"x-ngenix-cache",
            b"xkey",
        }
        forbidden_multiple_headers = {
            b"strict-transport-security",
            b"x-frame-options",
            b"x-content-type-options",
            b"retry-after",
            b"content-type",
            b"server",
            b"access-control-allow-origin",
            b"expires",
            b"age",
            b"report-to",
        }
        keys = set()
        all_duplicates = set()
        for key, _ in flow.response.headers.fields:
            """Ignore capitalization of headers"""
            key = key.lower()
            if key in keys:
                all_duplicates.add(key)
            else:
                keys.add(key)
        allowed_duplicates = all_duplicates & (
            allow_multiple_headers | allow_multiple_headers_custom
        )
        forbidden_duplicates = all_duplicates & forbidden_multiple_headers
        unclear_duplicates = all_duplicates - (
            allow_multiple_headers
            | allow_multiple_headers_custom
            | forbidden_multiple_headers
        )
        if len(all_duplicates):
            extra = f"Duplicates-Forbidden: {forbidden_duplicates}, Unclear: {unclear_duplicates}, Allowed: {allowed_duplicates}"
            if len(forbidden_duplicates):
                violation = Violation.INVALID
            elif len(unclear_duplicates):
                violation = Violation.UNCLEAR
            else:
                violation = Violation.VALID
            return ProbeTest(
                name=self.name, type=self.type, violation=violation, extra=extra
            )
        else:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Only headers that are allowed several times occur twice"""
        return (
            200,
            [("Content-Language", "mi"), ("Content-Language", "en")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Header that is not allowed to occur twice."""
        return 200, [("x-frame-options", "DENY"), ("x-frame-options", "SAMEORIGIN")], "<div>ABC</div>"


class content_length_1XX_204:
    title = """
    No Content-Length Header Field allowed for 1xx and 204
    """
    description = """
    A server MUST NOT send a Content-Length header field in any response with a status code of 1xx (Informational) or 204 (No Content).
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-content-length"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        status = flow.response.status_code
        if 100 <= status < 200 or status == 204:
            if flow.response.headers.get("Content-Length"):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
            else:
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """Return 204 without CL."""
        response.add_required_headers = False
        response.writer.write_status(204)
        response.writer.end_headers()

    def invalid(self, request, response):
        """Return 204 with CL."""
        return 204, [("Content-Length", 14)], "<div>ABC</div>"


class send_upgrade_426:
    title = """
    Send Upgrade Header field with 426
    """
    description = """
    A server that sends a 426 (Upgrade Required) response MUST send an Upgrade header field to indicate the acceptable protocols, in order of descending preference.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-upgrade"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 426:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Upgrade"):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """426 with upgrade header"""
        return 426, [("Upgrade", "HTTPS")], "<div>ABC</div>"

    def invalid(self, request, response):
        """426 without upgrade header"""
        return 426, [], "<div>ABC</div>"


class send_upgrade_101:
    title = """
    Server that sends a 101 response MUST send an Upgrade header field
    """
    description = """
    The Upgrade header field is intended to provide a simple mechanism for transitioning from HTTP/1.1 to some other protocol on the same connection. A server that sends a 101 (Switching Protocols) response MUST send an Upgrade header field to indicate the new protocol(s) to which the connection is being switched.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-upgrade"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 101:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Upgrade"):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """101 with Upgrade"""
        return 101, [("Upgrade", "HTTPS")], "<div>ABC</div>"

    def invalid(self, request, response):
        """101 without upgrade"""
        return 101, [], "<div>ABC</div>"


class switch_protocol_without_client:
    title = """
    A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding request's Upgrade header field
    """
    description = """
    A server MUST NOT switch to a protocol that was not indicated by the client in the corresponding requests Upgrade header field.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-upgrade"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Compare request upgrade header if upgrade is performed."""
        if flow.response.status_code != 101:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        client_upgrade = flow.request.headers.get("upgrade")
        server_upgrade = flow.response.headers.get("upgrade")
        if client_upgrade == server_upgrade:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Mirror client upgrade"""
        upgrade = request.headers.get("Upgrade")
        if upgrade is None:
            return 200, [], ""
        else:
            return 101, [("Upgrade", upgrade)], ""

    def invalid(self, request, response):
        """Distort client upgrade"""
        return (
            101,
            [("Upgrade", f"!not{request.headers.get('Upgrade')}")],
            "<div>ABC</div>",
        )


class cookie_grammar:
    title = """
    Cookies should follow the cookie grammar
    """
    description = """
    Each cookie begins with a name-value-pair, followed by zero or more attribute-value pairs. Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar: …
    """
    type = Level.ABNF
    category = "HTTP Cookies"
    source = "https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check for cookie grammar ~~(rely on redbot for this?)~~"""
        violation = Violation.INAPPLICABLE
        cookies = flow.response.headers.get_all("Set-Cookie")
        if cookies:
            violation = Violation.VALID
        for cookie in cookies:
            if not checks.check_cookie(cookie):
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid cookie"""
        return 200, [("Set-Cookie", "test=test")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid cookie"""
        return 200, [("Set-Cookie", "t,;est=test")], "<div>ABC</div>"


class duplicate_cookie_attribute:
    title = """
    Servers should not produce two attributes with the same name in the same set-cookie string
    """
    description = """
    To maximize compatibility with user agents, servers SHOULD NOT produce two attributes with the same name in the same set-cookie-string. (See Section 5.3 for how user agents handle this case.)
    """
    type = Level.RECOMMENDATION
    category = "HTTP Cookies"
    source = "https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Set-Cookie") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        cookie_headers = flow.response.headers.get_all("Set-Cookie")
        for cookie_header in cookie_headers:
            keys = []
            attribute = cookie_header.split(";")
            for assignment in attribute:
                key = assignment.split("=")[0]
                keys.append(key)
            if len(keys) != len(set(keys)):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """No cookie attribute occurs more than once."""
        return 200, [("Set-Cookie", "test=test; path=/")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Path attribute occurs twice."""
        return 200, [("Set-Cookie", "test=test; path=/; path=/abc")], "<div>ABC</div>"


class duplicate_cookies:
    title = """
    Should not include more than one Set-Cookie header field in the same response with the same cookie-name
    """
    description = """
    Servers SHOULD NOT include more than one Set-Cookie header field in the same response with the same cookie-name. (See Section 5.2 for how user agents handle this case.)
    """
    type = Level.RECOMMENDATION
    category = "HTTP Cookies"
    source = "https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Set-Cookie") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Set-Cookie")
        names = []
        for field in fields:
            """The name has to be the first entry, as header-folding of Set-Cookie is already tested somewhere else."""
            name = field.split(";")[0].split("=")[0]
            names.append(name)
        if len(names) != len(set(names)):
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Two different cookies"""
        return (
            200,
            [("Set-Cookie", "test=test; Secure"), ("Set-Cookie", "test2=test; Secure")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Two times the same cookie"""
        return (
            200,
            [("Set-Cookie", "test=test"), ("Set-Cookie", "test=test2")],
            "<div>ABC</div>",
        )


class cookie_IMF_fixdate:
    title = """
    Cookies should use IMF-fixdate
    """
    description = """
    Some existing user agents differ in their interpretation of two-digit years. To avoid compatibility issues, servers SHOULD use the rfc1123-date format, which requires a four-digit year.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Cookies"
    source = "https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Set-Cookie") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        cookies = flow.response.headers.get_all("Set-Cookie")
        for cookie in cookies:
            cookie = cookie.split(";")
            for assignment in cookie:
                parameter, *value = assignment.split("=", maxsplit=1)
                if parameter.strip().lower() == "expires":
                    if checks.check_imf_fixdate(value[0]) is False:
                        return ProbeTest(
                            name=self.name, type=self.type, violation=Violation.INVALID
                        )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Cookie with valid date"""
        return (
            200,
            [("Set-Cookie", "test=test; expires=Wed, 08 Mar 2023 15:14:45 GMT")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Cookie with invalid date (only two digit year)"""
        return (
            200,
            [("Set-Cookie", "test=test; expires=Wed, 08 Mar 23 15:14:45 GMT")],
            "<div>ABC</div>",
        )


class coep_grammar:
    title = """
    Follow COEP ABNF
    """
    description = """
    The Cross-Origin-Embedder-Policy has quite strict parsing rules.
    #Question: How to categorize (requirement?) non RFC specifications?
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://html.spec.whatwg.org/dev/origin.html#coep"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Cross-Origin-Embedder-Policy") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Cross-Origin-Embedder-Policy")
        if "," in field:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.INVALID,
                extra=f"COEP more than one value: {field}",
            )
        """Allow parameters in values, e.g., report-to; we do not check correctness of parameters currently"""
        field = field.split(";")[0]
        if field in ["unsafe-none", "require-corp", "credentialless"]:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.INVALID,
                extra=f"COEP: {field}",
            )

    def valid(self, request, response):
        """Valid COEP header."""
        return 200, [("Cross-Origin-Embedder-Policy", "unsafe-none")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid COEP header."""
        return 200, [("Cross-Origin-Embedder-Policy", "abc")], "<div>ABC</div>"


class corp_grammar:
    title = """
    Follow CORP ABNF
    """
    description = """
    Its value ABNF: Cross-Origin-Resource-Policy = %ssame-origin / %ssame-site / %scross-origin ; case-sensitive
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-cross-origin-resource-policy"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Cross-Origin-Resource-Policy") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Cross-Origin-Resource-Policy")
        if field in ["same-origin", "same-site", "cross-origin"]:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra=f"CORP: {field}",
        )

    def valid(self, request, response):
        """Valid CORP value."""
        return 200, [("Cross-Origin-Resource-Policy", "same-origin")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid CORP value."""
        return 200, [("Cross-Origin-Resource-Policy", "abc")], "<div>ABC</div>"


class csp_grammar:
    title = """
    Follow the CSP: ABNF
    """
    description = """
    The Content-Security-Policy HTTP response header following ABNF [RFC5234]: Content-Security-Policy = 1#serialized-policy
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-csp/#csp-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Security-Policy") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Content-Security-Policy")
        for field in fields:
            if not checks.check_csp(field):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid CSP Header"""
        return (
            200,
            [("Content-Security-Policy", "base-uri 'none'; default-src 'none';")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid CSP Header"""
        return 200, [("Content-Security-Policy", "base_uri 'none'")], "<div>ABC</div>"


class csp_ro_grammar:
    title = """
    CSP (Report Only): ABNF
    """
    description = """
    The Content-Security-Policy-Report-Only HTTP response header represented by the following ABNF [RFC5234]: Content-Security-Policy-Report-Only = 1#serialized-policy
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-csp/#cspro-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Security-Policy-Report-Only") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Content-Security-Policy-Report-Only")
        for field in fields:
            if not checks.check_csp(field):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid CSP-Ro"""
        return (
            200,
            [
                (
                    "Content-Security-Policy-Report-Only",
                    "base-uri 'none'; default-src 'none';",
                )
            ],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid CSP-Ro"""
        return (
            200,
            [("Content-Security-Policy-Report-Only", "base_uri 'none'")],
            "<div>ABC</div>",
        )


class permissions_policy_grammar:
    title = """
    Permissions Policy: ABNF
    """
    description = """
    The Permissions-Policy HTTP header field ABNF is: PermissionsPolicy = sh-dictionary
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-permissions-policy/#permissions-policy-http-header-field"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Permissions-Policy") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Permissions-Policy")
        for field in fields:
            if field == "":
                continue
            if not checks.check_sf_dictionary(field):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid permissionspolicy"""
        return 200, [("Permissions-Policy", "geolocation=()")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid permissionspolicy"""
        return 200, [("Permissions-Policy", "=abc;")], "<div>ABC</div>"


class xcto_grammar:
    title = """
    X-Content-Type-Options: ABNF
    """
    description = """
    The X-Content-Type-Options response header  value ABNF: X-Content-Type-Options  = nosniff
    (First value is used by browsers, if several exist)
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#x-content-type-options-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("X-Content-Type-Options") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("X-Content-Type-Options")
        for field in fields:
            field = field.lower()
            if field != "nosniff":
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Valid XCTO"""
        return 200, [("X-Content-Type-Options", "nosniff")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid XCTO"""
        return 200, [("X-Content-Type-Options", "yessniff")], "<div>ABC</div>"


class sts_grammar:
    title = """
    STS: ABNF
    """
    description = """
    The Strict-Transport-Security HTTP response header field  = Strict-Transport-Security : [ directive ]  *( ; [ directive ] ) \ directive   = directive-name [ = directive-value ] \ directive-name  = token \ directive-value = token | quoted-string \ where: token = <token, defined in [RFC2616], Section 2.2> \ quoted-string = <quoted-string, defined in [RFC2616], Section 2.2>
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc6797#section-6.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """STS ABNF check"""
        sts = flow.response.headers.get_all("Strict-Transport-Security")
        violation = Violation.VALID
        if len(sts) == 0:
            violation = Violation.INAPPLICABLE
        for header in sts:
            if not checks.check_sts(header):
                violation = violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid STS header"""
        return 200, [("Strict-Transport-Security", "max-age=0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid STS header"""
        return 200, [("Strict-Transport-Security", '"abc"')], "<div>ABC</div>"


class xfo_grammar:
    title = """
    X-Frame-Options ABNF
    """
    description = """
    X-Frame-Options = "DENY" / "SAMEORIGIN" (special rules apply for multiple values and legacy allowall; also note allow-from)
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://html.spec.whatwg.org/multipage/browsing-the-web.html#the-x-frame-options-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("X-Frame-Options") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("X-Frame-Options")
        fields = field.split(",")
        extra = []
        violation = Violation.VALID
        if len(fields) > 1:
            """Is invalid but does not have to cause harm, e.g., two DENY"""
            violation = Violation.INVALID
            extra.append("More than one value")
        for field in fields:
            field = field.lower().strip()
            if "allow-from" in field:
                violation = Violation.INVALID
                extra.append("Deprecated allow-from")
            elif "allowall" == field:
                violation = Violation.INVALID
                extra.append("Deprecated allowall")
            elif field in ["deny", "sameorigin"]:
                pass
            else:
                violation = Violation.INVALID
                extra.append(f"Invalid value: {field}")
        return ProbeTest(
            name=self.name, type=self.type, violation=violation, extra=", ".join(extra)
        )

    def valid(self, request, response):
        """Valid XFO header"""
        return 200, [("X-Frame-Options", "DENY")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid XFO header"""
        return 200, [("X-Frame-Options", "ABC, allowall")], "<div>ABC</div>"


class coop_grammar:
    title = """
    COOP possible values
    """
    description = """
    A cross-origin opener policy possible values are: unsafe-none, same-origin-allow-popups, same-origin, (same-origin-plus-COEP)
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policies"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Cross-Origin-Opener-Policy") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Cross-Origin-Opener-Policy")
        extra = []
        violation = Violation.VALID
        if len(fields) > 1:
            violation = Violation.INVALID
            extra.append("More than one COOP header")
        for field in fields:
            """Allow parameters in values, e.g., report-to; we do not check correctness of parameters currently"""
            field = field.split(";")[0]
            if field not in [
                "unsafe-none",
                "same-origin-allow-popups",
                "same-origin",
                "same-origin-plus-COEP",
            ]:
                violation = Violation.INVALID
                extra.append(f"Invalid value: {field}")
        return ProbeTest(
            name=self.name, type=self.type, violation=violation, extra=",".join(extra)
        )

    def valid(self, request, response):
        """Valid COOP"""
        return 200, [("Cross-Origin-Opener-Policy", "unsafe-none")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid COOP"""
        return 200, [("Cross-Origin-Opener-Policy", "unsafe_none")], "<div>ABC</div>"


class access_control_allow_origin_grammar:
    title = """
    Access-Control-Allow-Origin ABNF
    """
    description = """
    Access-Control-Allow-Origin  = origin-or-null / wildcard
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Allow-Origin") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Access-Control-Allow-Origin")
        violation = Violation.VALID
        extra = []
        if len(fields) > 1:
            violation = Violation.INVALID
            extra.append("ACAO more than one header")
        for field in fields:
            if not (field == "*" or checks.check_origin_or_null(field)):
                violation = Violation.INVALID
                extra.append(f"ACAO invalid value: {field}")
        return ProbeTest(
            name=self.name, type=self.type, violation=violation, extra=",".join(extra)
        )

    def valid(self, request, response):
        """Valid ACAO"""
        return 200, [("Access-Control-Allow-Origin", "*")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid ACAO"""
        return 200, [("Access-Control-Allow-Origin", "a,a")], "<div>ABC</div>"


class access_control_allow_credentials_grammar:
    title = """
    Access-Control-Allow-Credentials ABNF
    """
    description = """
    Access-Control-Allow-Credentials = %strue ; case-sensitive
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Allow-Credentials") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Access-Control-Allow-Credentials")
        if field == "true":
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra=f"Invalid ACAC: {field}",
        )

    def valid(self, request, response):
        """Valid ACAC"""
        return 200, [("Access-Control-Allow-Credentials", "true")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid ACAC"""
        return 200, [("Access-Control-Allow-Credentials", "false")], "<div>ABC</div>"


class access_control_expose_headers_grammar:
    title = """
    Access-Control-Expose-Headers ABNF
    """
    description = """
    Access-Control-Expose-Headers= #field-name
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Expose-Headers") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Access-Control-Expose-Headers")
        if checks.check_token_list(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid ACEH"""
        return (
            200,
            [("Access-Control-Expose-Headers", "Content-Length")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid ACEH"""
        return 200, [("Access-Control-Expose-Headers", '"a,a,;"')], "<div>ABC</div>"


class access_control_max_age_grammar:
    title = """
    Access-Control-Max-Age ABNF
    """
    description = """
    Access-Control-Max-Age   = delta-seconds
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Max-Age") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Access-Control-Max-Age")
        try:
            field = int(field)
            if field < 0:
                raise ValueError
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        except:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid ACMA"""
        return 200, [("Access-Control-Max-Age", "2")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid ACMA"""
        return 200, [("Access-Control-Max-Age", "abc")], "<div>ABC</div>"


class access_control_allow_methods_grammar:
    title = """
    Access-Control-Allow-Methods ABNF
    """
    description = """
    Access-Control-Allow-Methods = #method
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Allow-Methods") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Access-Control-Allow-Methods")
        if checks.check_token_list(field) or field == "*":
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid ACAM"""
        return 200, [("Access-Control-Allow-Methods", "GET")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid ACAM"""
        return 200, [("Access-Control-Allow-Methods", ", ;")], "<div>ABC</div>"


class access_control_allow_headers_grammar:
    title = """
    Access-Control-Allow-Headers ABNF
    """
    description = """
    Access-Control-Allow-Headers = #field-name
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://fetch.spec.whatwg.org/#http-new-header-syntax"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Access-Control-Allow-Headers") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Access-Control-Allow-Headers")
        if checks.check_token_list(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid ACAH"""
        return (
            200,
            [("Access-Control-Allow-Headers", "Content-Length")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid ACAH"""
        return 200, [("Access-Control-Allow-Headers", ",;.")], "<div>ABC</div>"


class age_grammar:
    title = """
    Age grammar
    """
    description = """
    Age = delta-seconds  The Age field-value is a non-negative integer, representing time in seconds.
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9111#field.age"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Age") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Age")
        try:
            field = int(field)
            if field < 0:
                raise ValueError
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        except:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid Age Header"""
        return 200, [("Age", "2")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Age Header"""
        return 200, [("Age", "abc")], "<div>ABC</div>"


class cache_control_grammar:
    title = """
    Cache-Control grammar
    """
    description = """
    Cache-Control   = #cache-directive
    cache-directive = token [ "=" ( token / quoted-string ) ]
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9111#field.cache-control"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check for cache-control grammar"""
        violation = Violation.INAPPLICABLE
        cc = flow.response.headers.get("Cache-Control")
        if cc:
            if checks.check_cache_control(cc):
                violation = Violation.VALID
            else:
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Cache-Control Header"""
        return 200, [("Cache-Control", "max-age=0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Cache-Control Header"""
        return 200, [("Cache-Control", ",.k;")], "<div>ABC</div>"


class server_grammar:
    title = """
    Server Header Field Grammar
    """
    description = """
    The Server header field  = product *( RWS ( product / comment ) )
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.server"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check server grammar"""
        violation = Violation.INAPPLICABLE
        server = flow.response.headers.get("Server")
        if server:
            if checks.check_server(server):
                violation = Violation.VALID
            else:
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Server header"""
        return 200, [("Server", "CERN/3.0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Server header"""
        return 200, [("Server", ",;<")], "<div>ABC</div>"


class retry_after_grammar:
    title = """
    Follow Retry-After grammar
    """
    description = """
    Retry-After = HTTP-date / delay-seconds  A delay-seconds value is a non-negative decimal integer, representing time in seconds.delay-seconds  = 1*DIGIT
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.retry-after"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Retry-After") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        fields = flow.response.headers.get_all("Retry-After")
        violation = Violation.VALID
        for field in fields:
            try:
                field = int(field)
                if field < 0:
                    raise ValueError
            except:
                date, d_type = checks.check_http_date(field)
                if not date:
                    violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Retry-After Date"""
        return 200, [("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Retry-After Date"""
        return 200, [("Retry-After", "Wed,21 Oct 2015 07:28:00 GMT")], "<div>ABC</div>"


class proxy_authorization_grammar:
    title = """
    Follows Proxy-Authorization grammar
    """
    description = """
    Proxy-Authorization = credentials (Client header?)
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.proxy-authorization"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check proxy-authorization grammar"""
        violation = Violation.INAPPLICABLE
        proxy_auth = flow.response.headers.get("Proxy-Authorization")
        if proxy_auth:
            if checks.check_proxy_authorization(proxy_auth):
                violation = Violation.VALID
            else:
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Proxy-Authorization"""
        return (
            200,
            [("Proxy-Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid Proxy-Authorization"""
        return 200, [("Proxy-Authorization", "y,.;")], "<div>ABC</div>"


class location_header_grammar:
    title = """
    Follows Location Header grammar
    """
    description = """
    Location = URI-reference.
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.location"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check location ABNF"""
        violation = Violation.INAPPLICABLE
        location = flow.response.headers.get("Location")
        if location:
            if checks.check_uri_reference(location):
                violation = Violation.VALID
            else:
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid location header"""
        return 200, [("Location", "/")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid location header"""
        return 200, [("Location", "., ,. ;")], "<div>ABC</div>"


class last_modified_grammar:
    title = """
    Follows Last-Modified grammar/abnf
    """
    description = """
    Last-Modified = HTTP-date
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.last-modified"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Last-Modified") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Last-Modified")
        date, d_type = checks.check_http_date(field)
        if date:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.VALID,
                extra=f"Date-Type: {d_type}",
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Last-Modified"""
        return (
            200,
            [("Last-Modified", "Tue, 15 Nov 1994 12:45:26 GMT")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid Last-Modified"""
        return 200, [("Last-Modified", "-5")], "<div>ABC</div>"


class expires_grammar:
    title = """
    Follows Expires Header field grammar
    """
    description = """
    Expires = HTTP-date
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9111#field.expires"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Expires") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Expires")
        date, d_type = checks.check_http_date(field)
        if date:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.VALID,
                extra=f"Date-Type: {d_type}",
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Expires"""
        return 200, [("Expires", "Thu, 01 Dec 1994 16:00:00 GMT")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid expires"""
        return 200, [("Expires", "-5")], "<div>ABC</div>"


class etag_grammar:
    title = """
    Follows Etag header field grammar
    """
    description = """
    ETag = entity-tag
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.etag"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check Etag follows grammar"""
        etag = flow.response.headers.get_all("ETag")
        violation = Violation.VALID
        if len(etag) == 0:
            violation = Violation.INAPPLICABLE
        for header in etag:
            if not checks.check_etag(header):
                violation = violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid ETag"""
        return 200, [("ETag", '"abc"')], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid ETag"""
        return 200, [("ETag", ",")], "<div>ABC</div>"


class date_grammar:
    title = """
    Follows Date header field grammar
    """
    description = """
    Date = HTTP-date
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.date"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Date") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Date")
        date, d_type = checks.check_http_date(field)
        if date:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.VALID,
                extra=f"Date-Type: {d_type}",
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Date"""
        return 200, [("Date", "Wed, 21 Oct 2015 07:28:00 GMT")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Date"""
        return 200, [("Date", "Wed,21 Oct 2015 07:28:00 GMT")], "<div>ABC</div>"


class content_type_grammar:
    title = """
    Follows Content-Type header grammar
    """
    description = """
    Content-Type = media-type
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-type"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        ct = flow.response.headers.get_all("content-type")
        violation = Violation.VALID
        if len(ct) == 0:
            violation = Violation.INAPPLICABLE
        for header in ct:
            if not checks.check_content_type(header):
                violation = violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Content-Type"""
        return (
            200,
            [("Content-Type", "text/html; charset=ISO-8859-4")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Invalid Content-Type"""
        return 200, [("Content-Type", ",;-")], "<div>ABC</div>"


class range_grammar:
    title = """
    Follows Content-Range header field grammar
    """
    description = """
    Content-Range       = range-unit SP
                        ( range-resp / unsatisfied-range )
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-range"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Range") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Content-Range")
        if checks.check_content_range(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Content-Range header"""
        return 206, [("Content-Range", "bytes 42-1233/*")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Content-Range header"""
        return 206, [("Content-Range", "-5")], "<div>ABC</div>"


class content_length_grammar:
    title = """
    Follows Content-Length header field grammar
    """
    description = """
    Content-Length = 1*DIGIT
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-length"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Length") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Content-Length")
        try:
            field = int(field)
            if field < 0:
                raise ValueError
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        except:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid content-length header"""
        return 200, [("Content-Length", "14")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid content-length header"""
        return 200, [("Content-Length", "abc")], "<div>ABC</div>"


class content_language_grammar:
    title = """
    Follows Content-Language header field grammar
    """
    description = """
    Content-Language = #language-tag
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-language"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Language") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Content-Language")
        if checks.check_content_language(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Content-Language header"""
        return 200, [("Content-Language", "mi, en")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Content-Language header"""
        return 200, [("Content-Language", "german")], "<div>ABC</div>"


class content_encoding_grammar:
    title = """
    Follows Content-Encoding header field grammar
    """
    description = """
    Content-Encoding = #content-coding
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Encoding") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Content-Encoding")
        if checks.check_token_list(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Content-Encoding header"""
        return 200, [("Content-Encoding", "coding")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Content-Encoding header"""
        return 200, [("Content-Encoding", ",;.")], "<div>ABC</div>"


class connection_grammar:
    title = """
    Connection header field grammar
    """
    description = """
    Connection        = #connection-option
    connection-option = token
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.connection"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Connection") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Connection")
        if checks.check_token_list(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Connection header"""
        return 200, [("Connection", "Option")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Connection header"""
        return 200, [("Connection", ",-")], "<div>ABC</div>"


class allow_grammar:
    title = """
    Allow Header field grammar
    """
    description = """
    Allow = #method
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.allow"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Allow") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Allow")
        if checks.check_allow(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Allow header"""
        return 200, [("Allow", "GET, HEAD, PUT")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Allow header"""
        return 200, [("Allow", "GET; HEAD; PUT")], "<div>ABC</div>"


class accept_ranges_grammar:
    title = """
    Follows Accept-Ranges Header field grammar
    """
    description = """
    Accept-Ranges     = acceptable-ranges
    acceptable-ranges = 1#range-unit
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.accept-ranges"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Accept-Ranges") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Accept-Ranges")
        if checks.check_accept_ranges(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Accept-Ranges header"""
        return 200, [("Accept-Ranges", "bytes")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Accept-Ranges header (empty list)"""
        return 200, [("Accept-Ranges", "")], "<div>ABC</div>"


class accept_encoding_grammar:
    title = """
    Follows Accept-Encoding grammar
    """
    description = """
    Accept-Encoding  = #( codings [ weight ] )
    codings          = content-coding / "identity" / "*"
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.accept-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check accept-encoding grammar"""
        ae = flow.response.headers.get("Accept-Encoding")
        if ae is None:
            result = Violation.INAPPLICABLE
        elif not checks.check_accept_encoding(ae):
            result = Violation.INVALID
        else:
            result = Violation.VALID
        return ProbeTest(name=self.name, type=self.type, violation=result)

    def valid(self, request, response):
        """Valid Accept-Encoding header"""
        return 200, [("Accept-Encoding", "gzip")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Accept-Encoding header"""
        return 200, [("Accept-Encoding", "(<>@")], "<div>ABC</div>"


class accept_patch_grammar:
    title = """
    Follows Accept-Patch grammar
    """
    description = """
    Accept-Patch = Accept-Patch : 1#media-type
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc5789#section-3.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Accept-Patch") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Accept-Patch")
        if checks.check_accept_patch(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Accept-Patch header"""
        return 200, [("Accept-Patch", "text/example;charset=utf-8")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Accept-Patch header"""
        return 200, [("Accept-Patch", ",@")], "<div>ABC</div>"


class transfer_encoding_grammar:
    title = """
    Follows Transfer-Encoding grammar
    """
    description = """
    Transfer-Encoding = #transfer-coding
                       ; defined in [HTTP], Section 10.1.4
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-transfer-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Transfer-Encoding") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Transfer-Encoding")
        if checks.check_transfer_encoding(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """Valid Transfer-Encoding"""
        response.writer.write_status(200)
        response.writer.write_header("Transfer-Encoding", "chunked")
        response.writer.end_headers()
        response.writer.write("4\r\nTest\r\n0\r\n\r\n")

    def invalid(self, request, response):
        """Invalid Transfer-Encoding"""
        return 200, [("Transfer-Encoding", "@,;")], "<div>ABC</div>"


class vary_grammar:
    title = """
    Follows Vary grammar
    """
    description = """
    Vary = #( "*" / field-name )
    """
    type = Level.ABNF
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-vary"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        vary = flow.response.headers.get_all("vary")
        violation = Violation.VALID
        if len(vary) == 0:
            violation = Violation.INAPPLICABLE
        for header in vary:
            if not checks.check_vary(header):
                violation = violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid Vary header"""
        return 200, [("Vary", "accept-encoding, accept-language")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid Vary header"""
        return 200, [("Vary", "")], "<div>ABC</div>"


class duplicate_csp:
    title = """
    CSP: Server should send only one CSP header
    """
    description = """
    A server SHOULD NOT send more than one HTTP response header field named Content-Security-Policy with a given resource representation.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-csp/#csp-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Security-Policy"):
            headers = flow.response.headers.get_all("Content-Security-Policy")
            if len(headers) > 1:
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
            else:
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """One CSP"""
        return 200, [("Content-Security-Policy", "abc")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Two CSPs"""
        return (
            200,
            [("Content-Security-Policy", "abc"), ("Content-Security-Policy", "123")],
            "<div>ABC</div>",
        )


class duplicate_csp_ro:
    title = """
    CSP (Report Only): Server should send only one CSP (Report Only) header
    """
    description = """
    A server SHOULD NOT send more than one HTTP response header field named Content-Security-Policy-Report-Only with a given resource representation.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-csp/#cspro-header"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Content-Security-Policy-Report-Only") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        headers = flow.response.headers.get_all("Content-Security-Policy-Report-Only")
        if len(headers) > 1:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        else:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """One CSP-RO"""
        return (
            200,
            [("Content-Security-Policy-Report-Only", "base-uri 'none'")],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """Two CSP-RO"""
        return (
            200,
            [
                ("Content-Security-Policy-Report-Only", "base-uri 'none'"),
                ("Content-Security-Policy-Report-Only", "base-uri 'none2'"),
            ],
            "<div>ABC</div>",
        )


class redirect_after_upgrade_insecure_requests:
    title = """
    Upgrade-Insecure-Requests: redirect if encountered
    """
    description = """
    When a server encounters this preference in an HTTP request's headers, it SHOULD redirect the user to a potentially trustworthy URL variant of the resource being requested.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-upgrade-insecure-requests/#preference"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.request.scheme == "http":
            if flow.request.headers.get("upgrade-insecure-requests"):
                location = flow.response.headers.get("location", "")
                if "https" in location:
                    return ProbeTest(
                        name=self.name, type=self.type, violation=Violation.VALID
                    )
                else:
                    return ProbeTest(
                        name=self.name, type=self.type, violation=Violation.INVALID
                    )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """Redirect to HTTPS if Upgrade-Insecure-Requests is encountered"""
        if request.headers.get("upgrade-insecure-requests"):
            return (
                307,
                [
                    ("Location", request.url.replace("http", "https")),
                    ("Vary", "Upgrade-Insecure-Requests"),
                ],
                "",
            )
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Do nothing"""
        return 200, [], "<div>ABC</div>"


class STS_header_after_upgrade_insecure_requests:
    title = """
    Upgrade-Insecure-Requests: include STS header in response
    """
    description = """
    When a server encounters this preference in an HTTPS request's headers, it SHOULD include a Strict-Transport-Security header in the response if the request's host is HSTS-safe or conditionally HSTS-safe [RFC6797].
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://w3c.github.io/webappsec-upgrade-insecure-requests/#preference"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.request.scheme == "https":
            if flow.request.headers.get("upgrade-insecure-requests"):
                hsts = flow.response.headers.get("strict-transport-security")
                if hsts:
                    return ProbeTest(
                        name=self.name, type=self.type, violation=Violation.VALID
                    )
                else:
                    return ProbeTest(
                        name=self.name,
                        type=self.type,
                        violation=Violation.INVALID,
                        extra="Or host not HSTS-safe",
                    )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """Return HSTS for upgrade-insecure-requests"""
        if request.headers.get("upgrade-insecure-requests"):
            return (
                307,
                [
                    ("Location", request.url.replace("http", "https")),
                    ("Vary", "Upgrade-Insecure-Requests"),
                    ("Strict-Transport-Security", "max-age=0"),
                ],
                "",
            )
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Do nothing for upgrade-insecure-requests"""
        return 200, [], "<div>ABC</div>"


class server_header_long:
    title = """
    No Overly Detailed Server Header fields
    """
    description = """
    An origin server SHOULD NOT generate a Server field containing needlessly fine-grained detail.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.server"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.headers.get("Server") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        field = flow.response.headers.get("Server")
        if len(field) > 100:
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.INVALID,
                extra=f"Very long server header: {field}",
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Normal server header"""
        return 200, [("Server", "abc")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Very long server header"""
        return 200, [("Server", 100 * "Serv")], "<div>ABC</div>"


class content_type_header_required:
    title = """
    A message with content should have a Content-Type header.
    """
    description = """
    A sender that generates a message containing content SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender.
    # (Add test that checks whether the content-encoding is valid, if flow.response.content raises, then it is not!)
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.content-type"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """If body is not empty, check if CT header exist"""
        violation = Violation.INAPPLICABLE
        if flow.response.raw_content:
            if flow.response.headers.get("Content-Type"):
                violation = Violation.VALID
            else:
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Content-Type header for response with body exist"""
        return 200, [("Content-Type", "text/html")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No Content-Type header for response without a body"""
        return 200, [], "<div>ABC</div>"


class sts_directives_only_allowed_once:
    title = """
    STS: directives must not appear more than once
    """
    description = """
    All directives MUST appear only once in an STS header field. Directives are either optional or required, as stipulated in their definitions.
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc6797#section-6.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Do not allow more than one directive in STS"""
        sts = flow.response.headers.get_all("Strict-Transport-Security")
        if len(sts) == 0:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        violation = Violation.VALID
        for h in sts:
            directives = [dir.strip().split("=")[0] for dir in h.split(";")]
            if len(directives) != len(set(directives)):
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid STS"""
        return 200, [("Strict-Transport-Security", "max-age=0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Invalid STS (duplicate directive)"""
        return (
            200,
            [("Strict-Transport-Security", "max-age=0; max-age=0")],
            "<div>ABC</div>",
        )


class only_one_sts_header_allowed:
    title = """
    Only one STS header allowed 
    """
    description = """
    If an STS header field is included, the HSTS Host MUST include only one such header field.
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc6797#section-7.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        fields = flow.response.headers.get_all("strict-transport-security")
        if len(fields) > 1:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        elif len(fields) == 1:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """One STS header"""
        return 200, [("Strict-Transport-Security", "max-age=0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Two STS headers"""
        return (
            200,
            [
                ("Strict-Transport-Security", "max-age=0"),
                ("Strict-Transport-Security", "max-age=0"),
            ],
            "<div>ABC</div>",
        )


class sts_header_http:
    title = """
    No STS header field for an HTTP request over non-secure transport
    """
    description = """
    An HSTS Host MUST NOT include the STS header field in HTTP responses conveyed over non-secure transport.
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc6797#section-7.2"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if not flow.response.headers.get("Strict-Transport-Security"):
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.request.scheme == "https":
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """No STS over HTTP (Real sanity check would need two requests, one over http and one over https)."""
        headers = []
        if request.url.startswith("https"):
            headers.append(("Strict-Transport-Security", "max-age=0"))
        return 200, headers, "<div>ABC</div>"

    def invalid(self, request, response):
        """STS over HTTP (always)"""
        return 200, [("Strict-Transport-Security", "max-age=0")], "<div>ABC</div>"


class date_header_required:
    title = """
    Date header field required for all statuscodes except 1xx and 5xx
    """
    description = """
    An origin server with a clock (as defined in Section 5.6.7) MUST generate a Date header field in all 2xx (Successful), 3xx (Redirection), and 4xx (Client Error) responses.
    (We cannot know if a server has a clock)
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9110#field.date"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        status = flow.response.status_code
        if status in range(100, 200) or status in range(500, 600):
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Date"):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra="Either server has no clock or missing required Date",
        )

    def valid(self, request, response):
        """Valid Date for 200"""
        return 200, [("Date", "Wed, 21 Oct 2015 07:28:00 GMT")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No Date for 200"""
        response.add_required_headers = False
        response.writer.write_status(200)
        response.writer.end_headers()


class no_transfer_encoding_1xx_204:
    title = """
    No transfer-encoding header allowed with 1xx, 204
    """
    description = """
    A server MUST NOT send a Transfer-Encoding header field in any response with a status code of 1xx (Informational) or 204 (No Content).
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9112#field.transfer-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        status = flow.response.status_code
        if 100 <= status < 200 or status == 204:
            if flow.response.headers.get("Transfer-Encoding"):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.INVALID
                )
            else:
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )

    def valid(self, request, response):
        """No Transfer-Encoding for 204"""
        return 204, [], ""

    def invalid(self, request, response):
        """Transfer-Encoding for 204"""
        return 204, [("Transfer-Encoding", "chunked")], ""


class transfer_encoding_http11:
    title = """
    A server MUST NOT send a response containing Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or later minor revisions)
    """
    description = """
    A server MUST NOT send a response containing Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or later minor revisions)
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc9112#field.transfer-encoding"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check http version if Transfer-Encoding exists (only HTTP/1.1 and higher minor versions allowed)"""
        violation = Violation.VALID
        extra = ""
        if flow.response.headers.get("Transfer-Encoding"):
            if flow.request.http_version != "HTTP/1.1":
                violation = Violation.INVALID
                extra = f"Use of Transfer-Encoding in {flow.request.http_version}"
        return ProbeTest(
            name=self.name, type=self.type, violation=violation, extra=extra
        )

    def valid(self, request, response):
        """Do not return transfer-encoding"""
        return 200, [], "<div>abc</div>"

    def invalid(self, request, response):
        """Always return transfer-encoding; (Problem: is not valid gzip thus mitmproxy has problems with the response)"""
        return 200, [("Transfer-Encoding", "gzip")], "abc"


class sts_max_age:
    title = """
    max-age directive is required in STS header
    """
    description = """
    The REQUIRED "max-age" directive specifies the number of seconds,
    """
    type = Level.REQUIREMENT
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc6797#section-6.1.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Max-Age has to be in STS header"""
        sts = flow.response.headers.get("Strict-Transport-Security")
        if sts is None:
            violation = Violation.INAPPLICABLE
        elif "max-age" in sts:
            violation = Violation.VALID
        else:
            violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Max-Age in STS header"""
        return 200, [("Strict-Transport-Security", "max-age=0")], "<div>ABC</div>"

    def invalid(self, request, response):
        """NO Max-Age in STS header"""
        return (
            200,
            [("Strict-Transport-Security", "includeSubDomains")],
            "<div>ABC</div>",
        )


class post_invalid_response_codes:
    title = """
    Status-Codes 206, 304, 416 are not allowed as answers to POST requests
    """
    description = """
    Almost all of the status codes defined by this specification could be received in a response to POST (the exceptions being 206 (Partial Content), 304 (Not Modified), and 416 (Range Not Satisfiable)).
    """
    type = Level.REQUIREMENT
    category = "HTTP Methods"
    source = "https://www.rfc-editor.org/rfc/rfc9110#POST"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check if invalid codes are returned for POST requests"""
        violation = Violation.INAPPLICABLE
        if flow.request.method == "POST":
            if flow.response.status_code in [206, 304, 416]:
                violation = Violation.INVALID
            else:
                violation = Violation.VALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Return 206 except for POST, where return 200"""
        code = 206
        if request.method == "POST":
            code = 200
        return code, [], "<div>abc</div>"

    def invalid(self, request, response):
        """Always return 206"""
        return 206, [], "<div>abc</div>"


class close_option_in_final_response:
    title = """
    Server SHOULD send a "close" connection option in its final response on that connection (request with connection close)
    """
    description = """
    The server SHOULD send a "close" connection option in its final response on that connection.
    """
    type = Level.RECOMMENDATION
    category = "HTTP/1.1"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-tear-down"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        field = flow.request.headers.get("Connection")
        if field != "close":
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        else:
            field = flow.response.headers.get("Connection")
            if field == "close":
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Always send connection close."""
        return 200, [("Connection", "close")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Never send connection close"""
        return 200, [], "<div>ABC</div>"


class no_bare_cr:
    title = """
    Server must not generate bare CR (outside of the content)
    """
    description = """
    A sender MUST NOT generate a bare CR (a CR character not immediately followed by LF) within any protocol elements other than the content.
    """
    type = Level.REQUIREMENT
    category = "HTTP/1.1"
    source = "https://www.rfc-editor.org/rfc/rfc9112#name-message-parsing"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check for bare CR in HTTP1 response head"""
        violation = Violation.INAPPLICABLE
        if not flow.response.is_http2:
            violation = Violation.VALID
            if re.search(
                b"\r(?!\n)",
                net.http.http1.assemble.assemble_response_head(flow.response),
            ):
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """No bare CR"""
        response.writer.write_status(200)
        response.writer.write_header("A", "1\r\nB: 2")
        response.writer.end_headers()

    def invalid(self, request, response):
        """Return a bare CR in header"""
        response.writer.write_status(200)
        response.writer.write_header("A\r", "1\rB: 2")
        response.writer.end_headers()


class code_101_not_allowed_in_http2:
    title = """
    101 SWITCHING PROTOCOLS: not allowed in http2
    """
    description = """
    HTTP/2 does not support the 101 (Switching Protocols) informational status code (Section 15.2.2 of [HTTP]).
    """
    type = Level.REQUIREMENT
    category = "HTTP/2"
    source = "https://www.rfc-editor.org/rfc/rfc9113#name-the-upgrade-header-field"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Mostly catched before: Informational responses are swallowed by MITMProxy and result in HTTP/2 protocol error: cannot receive data before headers"""
        if flow.response.status_code != 101:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        elif flow.request.is_http2:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        else:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Do not send 101 for http2"""
        print(request.protocol_version)
        if "2" in request.protocol_version:
            return 200, [], "<div>ABC</div>"
        else:
            return 101, [], ""

    def invalid(self, request, response):
        """Send 101 (even in http2)"""
        return 101, [], ""


class field_name_nonvisible_asciichars:
    title = """
    Field name must not contain non-visible ASCII characters, ASCII SP, or uppercase characters
    """
    description = """
    A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all ranges inclusive). This specifically excludes all non-visible ASCII characters, ASCII SP (0x20), and uppercase characters (A to Z, ASCII 0x41 to 0x5a).
    """
    type = Level.REQUIREMENT
    category = "HTTP/2"
    source = "https://www.rfc-editor.org/rfc/rfc9113#name-field-validity"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check for forbidden characters in http2 responses (mitmproxy might already throw errors for some of them)"""
        violation = Violation.INAPPLICABLE
        if flow.response.is_http2:
            violation = Violation.VALID
            for header in flow.response.headers:
                if re.search("[\\x00-\\x20\\x41-\\x5a\\x7f-\\xff]", header):
                    violation = Violation.INVALID
                    break
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Return valid HTTP2 response"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Return an invalid HTTP2 response (field name forbidden character)"""
        return 200, [("t est", "whitespace")], "<div>ABC</div>"


class field_name_colon_except_for_pseudo_header_fields:
    title = """
    Field name must not contain colon names except for pseudo-header fields
    """
    description = """
    With the exception of pseudo-header fields (Section 8.3), which have a name that starts with a single colon, field names MUST NOT include a colon (ASCII COLON, 0x3a).
    """
    type = Level.REQUIREMENT
    category = "HTTP/2"
    source = "https://www.rfc-editor.org/rfc/rfc9113#name-field-validity"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check if HTTP/2 headers contain colon (other than pseudo-headers)"""
        violation = Violation.INAPPLICABLE
        if flow.response.is_http2:
            violation = Violation.VALID
            for header in flow.response.headers:
                if ":" in header:
                    violation = Violation.INVALID
                    break
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Send valid responses"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Send http2 response with colon in header name; not allowed at start from wptserve + autolowers :(
        MITMProxy makes a linear parse of the headers to split in pseudo/normal
        """
        return 200, [("a:Bc", "test")], "<div>ABC</div>"


class field_value_zero_value_lf_cr:
    title = """
    Field value must not contain zero value, line feed or carriage return
    """
    description = """
    A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.
    """
    type = Level.REQUIREMENT
    category = "HTTP/2"
    source = "https://www.rfc-editor.org/rfc/rfc9113#name-field-validity"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check field values"""
        violation = Violation.INAPPLICABLE
        if flow.response.is_http2:
            violation = Violation.VALID
            for _, value in flow.response.headers.fields:
                if re.search(b"[\\x00\\x0a\\x0d]", value):
                    violation = Violation.INVALID
                    break
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Valid HTTP2 response"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Send invalid http2 response, invalid char in field value"""
        return 200, [("invalid", b"\x00")], "<div>ABC</div>"


class field_value_start_or_end_with_whitespace:
    title = """
    Field value must not start or end with whitespace
    """
    description = """
    A field value MUST NOT start or end with an ASCII whitespace character (ASCII SP or HTAB, 0x20 or 0x09).
    """
    type = Level.REQUIREMENT
    category = "HTTP/2"
    source = "https://www.rfc-editor.org/rfc/rfc9113#name-field-validity"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check http2 headers for spaces"""
        violation = Violation.INAPPLICABLE
        extra = ""
        if flow.response.is_http2:
            violation = Violation.VALID
            for header, value in flow.response.headers.fields:
                if len(value) != 0:
                    val = bytes(chr(value[0]), "utf8") + bytes(chr(value[-1]), "utf8")
                    if re.search(b"[\\x20\\x09]", val):
                        violation = Violation.INVALID
                        extra = f"{header}: {value}"
                        break
        return ProbeTest(
            name=self.name, type=self.type, violation=violation, extra=extra
        )

    def valid(self, request, response):
        """Valid HTTP2 response"""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Fails: invalid http2 response header field starts with space; problem spaces get stripped by wptserve"""
        return 200, [("invalid", b" \t")], "<div>ABC</div>"


class code_300_location:
    title = """
    300 MULTIPLE CHOICES: location header field in response
    """
    description = """
    If the server has a preferred choice, the server SHOULD generate a Location header field containing a preferred choices URI reference.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-300-multiple-choices"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 300:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        field = flow.response.headers.get("Location")
        if checks.check_uri_reference(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra=f"Location not a valid URI reference: {field}",
        )

    def valid(self, request, response):
        """Location with 300"""
        return 300, [("Location", "/People.html#tim")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No location with 300"""
        return 300, [], "<div>ABC</div>"


class code_300_metadata:
    title = """
    300 MULTIPLE CHOICES: response should not be empty
    """
    description = """
    For request methods other than HEAD, the server SHOULD generate content in the 300 response containing a list of representation metadata and URI reference(s) from which the user or user agent can choose the one most preferred
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-300-multiple-choices"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 300 or flow.request.method == "HEAD":
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if len(flow.response.content):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """300 with body content"""
        return 300, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """300 without body content"""
        return 300, [], ""


class code_301_location:
    title = """
    301 MOVED PERMANENTLY: location header field
    """
    description = """
    The server SHOULD generate a Location header field in the response containing a preferred URI reference for the new permanent URI.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-301-moved-permanently"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 301:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """Location in 301"""
        return 301, [("Location", "http://127.0.0.1:5000")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No location for 301"""
        return 301, [], "<div>ABC</div>"


class code_302_location:
    title = """
    302 FOUND: location header field
    """
    description = """
    The server SHOULD generate a Location header field in the response containing a URI reference for the different URI. The user agent MAY use the Location field value for automatic redirection. The servers response content usually contains a short hypertext note with a hyperlink to the different URI(s).
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-302-found"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 302:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        field = flow.response.headers.get("Location")
        if checks.check_uri_reference(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra=f"Invalid URI: {field}",
        )

    def valid(self, request, response):
        """302 with location"""
        return 302, [("Location", "http://127.0.0.1:5000")], "<div>ABC</div>"

    def invalid(self, request, response):
        """302 without location"""
        return 302, [], "<div>ABC</div>"


class code_303_location:
    title = """
    303 SEE OTHER: should have a location field
    """
    description = """
    The 303 (See Other) should have a location field.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-303-see-other"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 303:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        field = flow.response.headers.get("Location")
        if checks.check_uri_reference(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra=f"Invalid uri: {field}",
        )

    def valid(self, request, response):
        """303 with location"""
        return 303, [("Location", "http://127.0.0.1:5000")], "<div>ABC</div>"

    def invalid(self, request, response):
        """303 without location"""
        return 303, [], "<div>ABC</div>"


class code_307_location:
    title = """
    307 TEMPORARY REDIRECT: should have a location
    """
    description = """
    The 307 (Temporary Redirect) status code should have a location.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-307-temporary-redirect"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 307:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location"):
            field = flow.response.headers.get("Location")
            if checks.check_uri_reference(field):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.INVALID,
                extra=f"Invalid URI: {field}",
            )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """Valid location for 307"""
        return 307, [("Location", "http://127.0.0.1:5000")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No location for 307"""
        return 307, [], "<div>ABC</div>"


class code_308_location:
    title = """
    308 PERMANENTLY REDIRECT: location header field
    """
    description = """
    The server SHOULD generate a Location header field in the response containing a preferred URI reference for the new permanent URI.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-308-permanent-redirect"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 308:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Location"):
            field = flow.response.headers.get("Location")
            if checks.check_uri_reference(field):
                return ProbeTest(
                    name=self.name, type=self.type, violation=Violation.VALID
                )
            return ProbeTest(
                name=self.name,
                type=self.type,
                violation=Violation.INVALID,
                extra=f"Invalid URI: {field}",
            )
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """308 with location"""
        return 308, [("Location", "http://127.0.0.1:5000")], "<div>ABC</div>"

    def invalid(self, request, response):
        """308 without location"""
        return 308, [], "<div>ABC</div>"


class code_413_retry_after:
    title = """
    Server should send retry-after header if code 413 is temporary
    """
    description = """
    The 413 (Content Too Large) status code indicates that the server is refusing to process a request because the request content is larger than the server is willing or able to process. If the condition is temporary, the server SHOULD generate a Retry-After header field to indicate that it is temporary.
    (problem; we do not know whether it is temporary or not)
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-413-content-too-large"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 413:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Retry-After") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """413 with retry after"""
        return 413, [("Retry-After", 10)], "<div>ABC</div>"

    def invalid(self, request, response):
        """413 without retry after"""
        return 413, [], "<div>ABC</div>"


class code_415_unsupported_media_type:
    title = """
    415 UNSUPPORTED MEDIA TYPE: should have Accept-Encoding or Accept response header
    """
    description = """
    The 415 (Unsupported Media Type) status code indicates that the origin server is refusing to service the request because the content is in a format not supported by this method on the target resource. The format problem might be due to the requests indicated Content-Type or Content-Encoding, or as a result of inspecting the data directly. If the problem was caused by an unsupported content coding, the Accept-Encoding response header field (Section 12.5.3) ought to be used to indicate which (if any) content codings would have been accepted in the request. On the other hand, if the cause was an unsupported media type, the Accept response header field (Section 12.5.1) can be used to indicate which media types would have been accepted in the request.
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-415-unsupported-media-type"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 415:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Accept-Encoding") is not None:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        if flow.response.headers.get("Accept") is not None:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(name=self.name, type=self.type, violation=Violation.INVALID)

    def valid(self, request, response):
        """415 with accept"""
        return 415, [("Accept", "")], "<div>ABC</div>"

    def invalid(self, request, response):
        """415 without accept or accept-encoding"""
        return 415, [], "<div>ABC</div>"


class code_416_content_range:
    title = """
    416 RANGE NOT SATISFIABLE: should have a content-range header
    """
    description = """
    A server that generates a 416 response to a byte-range request SHOULD generate a Content-Range header field specifying the current length of the selected representation (Section 14.4).
    """
    type = Level.RECOMMENDATION
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-416-range-not-satisfiable"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 416:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Content-Range") is None:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        field = flow.response.headers.get("Content-Range")
        if checks.check_content_range(field):
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        return ProbeTest(
            name=self.name,
            type=self.type,
            violation=Violation.INVALID,
            extra="Invalid content-range",
        )

    def valid(self, request, response):
        """416 with valid content-range"""
        return 416, [("Content-Range", "bytes */47022")], "<div>ABC</div>"

    def invalid(self, request, response):
        """416 with invalid content-range"""
        return 416, [("Content-Range", ",;")], "<div>ABC</div>"


class code_204_no_additional_content:
    title = """
    204 NO CONTENT: server has successfully fulfilled the request and that there is no additional content to send in the response content
    """
    description = """
    Responses with statuscode 204 are not allowed to have anything after the header section.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-204-no-content"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """For HTTP1 this is catched by MITMProxy, for HTTP2 we can process it here"""
        violation = Violation.INAPPLICABLE
        if flow.response.status_code == 204:
            violation = Violation.VALID
            if len(flow.response.content):
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """204 without a body"""
        return 204, [], ""

    def invalid(self, request, response):
        """204 with body"""
        return 204, [], "<div>ABC</div>"


class code_205_no_content_allowed:
    title = """
    205 RESET CONTENT: no content allowed
    """
    description = """
    No content is allowed for statuscode 205
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-205-reset-content"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 205:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if len(flow.response.content):
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )
        return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)

    def valid(self, request, response):
        """No Content in 205 response"""
        return 205, [], ""

    def invalid(self, request, response):
        """Content in 205 response"""
        return 205, [], "<div>ABC</div>"


class code_206_content_range:
    title = """
    206 PARTIAL CONTENT: server MUST generate Content-Range header field or Content-Type has to be multipart/byteranges
    """
    description = """
    If a single part is being transferred, the server generating the 206 response MUST generate a Content-Range header field, describing what range of the selected representation is enclosed, and a content consisting of the range.
    If multiple parts are being transferred, the server generating the 206 response MUST generate multipart/byteranges content, as defined in Section 14.6, and a Content-Type header field containing the multipart/byteranges media type and its required boundary parameter.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-single-part"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check for content-range header or content-type multipart/byteranges if code is 206 (do not check correctness)"""
        violation = Violation.INAPPLICABLE
        if flow.response.status_code == 206:
            violation = Violation.INVALID
            if flow.response.headers.get("content-range"):
                violation = Violation.VALID
            else:
                ct = flow.response.headers.get("Content-Type", "")
                if "multipart/byteranges" in ct:
                    violation = Violation.VALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Correct Content-Range with 206"""
        return 206, [("Content-Range", "bytes 0-14/14")], "<div>ABC</div>"

    def invalid(self, request, response):
        """No Content-Range with 206"""
        return 206, [], "<div>ABC</div>"


class code_206_content_range_of_multiple_part_response:
    title = """
    206 PARTIAL CONTENT: Content-Range header and multipart/bytes not allowed at the same time
    """
    description = """
    To avoid confusion with single-part responses, a server MUST NOT generate a Content-Range header field in the HTTP header section of a multiple part response (this field will be sent in each part instead).
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-multiple-parts"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """Check if multipart/byterages and content-range occur at the same time for 206"""
        violation = Violation.INAPPLICABLE
        if flow.response.status_code == 206:
            violation = Violation.VALID
            if flow.response.headers.get("content-range"):
                ct = flow.response.headers.get("Content-Type", "")
                if "multipart/byteranges" in ct:
                    violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Only Content-Range for 206"""
        return 206, [("Content-Range", "bytes 0-14/14")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Content-Range and multipart/byteranges for 206"""
        return (
            206,
            [
                ("Content-Range", "bytes 0-14/14"),
                ("Content-Type", "multipart/byteranges; boundary=A"),
            ],
            "<div>ABC</div>",
        )


class code_401_www_authenticate:
    title = """
    401 UNAUTHORIZED: server generating a 401 response MUST send a WWW-Authenticate header field containing at least one challenge applicable to the target resource
    """
    description = """
    The 401 (Unauthorized) status code indicates that the request has not been applied because it lacks valid authentication credentials for the target resource. The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one challenge applicable to the target resource.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-401-unauthorized"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 401:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("WWW-Authenticate"):
            """Add check if challenge is valid?"""
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """401 with valid challenge"""
        return (
            401,
            [
                (
                    "WWW-Authenticate",
                    'Basic realm="simple", Newauth realm="apps", type=1',
                )
            ],
            "<div>ABC</div>",
        )

    def invalid(self, request, response):
        """401 without challenge"""
        return 401, [], "<div>ABC</div>"


class code_405_allow:
    title = """
    405 METHOD NOT ALLOWED: allow header field required
    """
    description = """
    The origin server MUST generate an Allow header field in a 405 response containing a list of the target resources currently supported methods
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-405-method-not-allowed"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 405:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        allow = flow.response.headers.get("Allow")
        if allow:
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            if allow is None:
                extra = "No allow header"
            else:
                extra = f"Allow header: {allow}"
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID, extra=extra
            )

    def valid(self, request, response):
        """405 with allow header"""
        return 405, [("Allow", "abc")], "<div>ABC</div>"

    def invalid(self, request, response):
        """405 without allow header"""
        return 405, [], "<div>ABC</div>"


class code_407_proxy_authenticate:
    title = """
    407 PROXY AUTHENTICATION REQUIRED:  similar to 401 (Unauthorized), but it indicates that the client needs to authenticate itself in order to use a proxy for this request
    """
    description = """
    The proxy MUST send a Proxy-Authenticate header field (Section 11.7.1) containing a challenge applicable to that proxy for the request.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-407-proxy-authentication-re"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        if flow.response.status_code != 407:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INAPPLICABLE
            )
        if flow.response.headers.get("Proxy-Authenticate") is not None:
            """Also verify that header is valid?"""
            return ProbeTest(name=self.name, type=self.type, violation=Violation.VALID)
        else:
            return ProbeTest(
                name=self.name, type=self.type, violation=Violation.INVALID
            )

    def valid(self, request, response):
        """407 with (valid) authentication challenge"""
        return 407, [("Proxy-Authenticate", "")], "<div>ABC</div>"

    def invalid(self, request, response):
        """407 without auth challenge"""
        return 407, [], "<div>ABC</div>"


class code_304_no_content:
    title = """
    No content allowed for statuscode 304
    """
    description = """
     A 304 response is terminated by the end of the header section; it cannot contain content or trailers.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-304-not-modified"
    name = sys._getframe().f_code.co_name
    activity = Activity.PROXY

    def test(self, flow: http.HTTPFlow) -> ProbeTest:
        """For HTTP1 this is catched by MITMProxy ('Unexpected data from server'), for HTTP2 we can process it here"""
        violation = Violation.INAPPLICABLE
        if flow.response.status_code == 304:
            violation = Violation.VALID
            if len(flow.response.raw_content):
                violation = Violation.INVALID
        return ProbeTest(name=self.name, type=self.type, violation=violation)

    def valid(self, request, response):
        """Return 304 without content"""
        return 304, [], ""

    def invalid(self, request, response):
        """Return 304 with content"""
        return 304, [], "<div>ABC</div>"


class content_length_same_head_get:
    title = """
    If Content-Length is returned to HEAD request it has to be the same as in GET.
    """
    description = """
    A server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method.
    Inapplicable: no cl
    Valid: same cl
    Invalid: different cl
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-content-length"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        violation = set("ina")
        extra = ""
        h_rs = req_resps.where(
            ReqResp.req_method == "'HEAD'", ReqResp.req_type == "proxy-probe"
        )
        pairs = []
        for h_r in h_rs:
            probe_ids = re.sub(
                "\\((\\d+), (\\d+), (\\d+)\\)", "(%, \\2, \\3)", h_r.probe_id
            )
            g_r = req_resps.where(
                ReqResp.req_method == "'GET'", ReqResp.probe_id % probe_ids
            )
            if g_r:
                pairs.append((h_r, g_r[0]))
        for h, g in pairs:
            h_len = int(parse_headers(h.resp_headers).get("content-length", -1))
            g_len = int(parse_headers(g.resp_headers).get("content-length", -1))
            h.probe_id
            if h_len > -1:
                violation.add("val")
                if h_len != g_len:
                    violation.add("inv")
                    extra += f"({h.probe_id}): head cl={h_len}, get cl={g_len}, "
        if "inv" in violation:
            v = Violation.INVALID
        elif "val" in violation:
            v = Violation.VALID
        else:
            v = Violation.INAPPLICABLE
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """Send same CL for both HEAD and GET."""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Send shorter CL to HEAD."""
        if request.method == "HEAD":
            headers = [("Content-Length", 10)]
        else:
            headers = [("Content-Length", 14)]
        return 200, headers, "<div>ABC</div>"


class content_length_same_304_200:
    title = """
    If Content-Length returned for conditional GET request (304), it has to be the same as for normal GET request (200)
    """
    description = """
    A server MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request (Section 15.4.5). A server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a 200 (OK) response to the same request.
    """
    type = Level.REQUIREMENT
    category = "HTTP"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-content-length"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        """We compare conditional GET with normal GET (if content-length to 304 is equal to any 200 GET length, we count it as valid)."""
        v = Violation.INAPPLICABLE
        extra = ""
        g_rs = req_resps.where(
            ReqResp.req_method == "'GET'", ReqResp.req_type == "proxy-probe"
        )
        lengths_200 = set()
        lengths_304 = set()
        for g in g_rs:
            g_len = int(parse_headers(g.resp_headers).get("content-length", -1))
            g_code = g.resp_code
            if g_code == "'200'" and g_len != -1:
                lengths_200.add(g_len)
            elif g_code == "'304'" and g_len != -1:
                lengths_304.add(g_len)
            else:
                pass
        if lengths_304:
            v = Violation.VALID
            if not all([(length_304 in lengths_200) for length_304 in lengths_304]):
                v = Violation.INVALID
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """Return same CL for conditional GET and normal GET."""
        if request.headers.get("If-Modified-Since"):
            return 304, [("Content-Length", 14)], ""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Return different CL for conditional GET and normal GET"""
        if request.headers.get("If-Modified-Since"):
            return 304, [("Content-Length", "200")], ""
        return 200, [], "<div>ABC</div>"


class accept_patch_presence:
    title = """
    Accept-Patch should appear where PATCH is supported
    """
    description = """
    Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Headers"
    source = "https://www.rfc-editor.org/rfc/rfc5789#section-3.1"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        """If patch request is accepted (code 200?) and response to options does not show accept-patch this is violated"""
        violation = set("ina")
        extra = ""
        p_rs = req_resps.where(
            ReqResp.req_method == "'PATCH'", ReqResp.req_type == "proxy-probe"
        )
        pairs = []
        for p_r in p_rs:
            probe_ids = re.sub(
                "\\((\\d+), (\\d+), (\\d+)\\)", "(%, \\2, \\3)", p_r.probe_id
            )
            o_r = req_resps.where(
                ReqResp.req_method == "'OPTIONS'", ReqResp.probe_id % probe_ids
            )
            if o_r:
                pairs.append((p_r, o_r[0]))
        for p, o in pairs:
            if p.resp_code == "'200'":
                o_h = parse_headers(o.resp_headers)
                violation.add("val")
                if o_h.get("Accept-Patch") is None:
                    violation.add("inv")
                    extra = f"Allows patch but no accept-patch header"
        if "inv" in violation:
            v = Violation.INVALID
        elif "val" in violation:
            v = Violation.VALID
        else:
            v = Violation.INAPPLICABLE
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """Send Accept-Patch and allowing patch"""
        return 200, [("Accept-Patch", "text/html")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Do not send Accept-Patch and allowing patch"""
        return 200, [], "<div>ABC</div>"


class head_get_headers:
    title = """
    Same header fields for HEAD and GET
    """
    description = """
    The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET.
    """
    type = Level.RECOMMENDATION
    category = "HTTP Methods"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-head"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        """Compare HEAD/GET requests: should have same response code and same header fields. Currently, we only compare header names. Some headers are allowed to only occur for GET requests: e.g., content-length."""
        violation = set(["val"])
        extra = ""
        codes = []
        headers_only = set()
        h_rs = req_resps.where(
            ReqResp.req_method == "'HEAD'", ReqResp.req_type == "proxy-probe"
        )
        pairs = []
        for h_r in h_rs:
            probe_ids = re.sub(
                "\\((\\d+), (\\d+), (\\d+)\\)", "(%, \\2, \\3)", h_r.probe_id
            )
            g_r = req_resps.where(
                ReqResp.req_method == "'GET'", ReqResp.probe_id % probe_ids
            )
            if g_r:
                pairs.append((h_r, g_r[0]))
        for h, g in pairs:
            if h.resp_code != g.resp_code:
                violation.add("inv")
                codes.append((g.resp_code, h.resp_code))
                continue
            h_headers = parse_headers(h.resp_headers)
            g_headers = parse_headers(g.resp_headers)
            """This set is controversial? Analyze it at a later stage?"""
            allowed_headers = set(
                ["content-length", "vary", "transfer-encoding", "content-encoding"]
            )
            h_fields = (
                set([h.lower() for h in h_headers.keys(multi=False)]) - allowed_headers
            )
            g_fields = (
                set([h.lower() for h in g_headers.keys(multi=False)]) - allowed_headers
            )
            if h_fields != g_fields:
                violation.add("inv")
                headers_only = headers_only | h_fields ^ g_fields
        if codes:
            extra += f"Different reponse codes: G,H={codes}"
        if headers_only:
            extra += f"Headers only in head or get: {headers_only}"
        if "inv" in violation:
            v = Violation.INVALID
        elif "val" in violation:
            v = Violation.VALID
        else:
            v = Violation.INAPPLICABLE
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """Send same headers for HEAD and GET except Date."""
        return 200, [], "<div>ABC</div>"

    def invalid(self, request, response):
        """Send GET/HEAD specific headers. (case matters)"""
        headers = []
        headers.append((request.method, f"{request.method} request!"))
        headers.append(("Any", request.method))
        return 200, headers, "<div>ABC</div>"


class code_206_headers:
    title = """
    206 PARTIAL CONTENT: server MUST generate some headers (if they occur in 200 responses to non-ranged requests)
    """
    description = """
    A server that generates a 206 response MUST generate the following header fields, in addition to those required in the subsections below, if the field would have been sent in a 200 (OK) response to the same request: Date, Cache-Control, ETag, Expires, Content-Location, and Vary.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-206-partial-content"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        """If a range request got 206, and the same request without a range header got 200, check the required headers (only if the occur for the 200 response)"""
        violation = set("ina")
        extra = ""
        headers_missing = set()
        r_rs = req_resps.where(
            ReqResp.req_type == "proxy-probe", ReqResp.probe_id % "(%, 3, %)"
        )
        for r_r in r_rs:
            if r_r.resp_code == "'206'":
                probe_id = re.sub(
                    "\\((\\d+), (\\d+), (\\d+)\\)", "(\\1, 1, \\3)", r_r.probe_id
                )
                n_r = req_resps.where(ReqResp.probe_id == probe_id)[0]
                if n_r.resp_code == "'200'":
                    violation.add("val")
                    r_headers = parse_headers(r_r.resp_headers)
                    n_headers = parse_headers(n_r.resp_headers)
                    required_headers = set(
                        [
                            "date",
                            "cache-control",
                            "etag",
                            "expires",
                            "content-location",
                            "vary",
                        ]
                    )
                    missing_headers = required_headers - set(
                        [h.lower() for h in r_headers.keys(multi=False)]
                    )
                    missing_headers_get = missing_headers - set(
                        [h.lower() for h in n_headers.keys(multi=False)]
                    )
                    if missing_headers and missing_headers != missing_headers_get:
                        violation.add("inv")
                        headers_missing = headers_missing | missing_headers
        if headers_missing:
            extra += f"Headers missing for 206: {headers_missing}"
        if "inv" in violation:
            v = Violation.INVALID
        elif "val" in violation:
            v = Violation.VALID
        else:
            v = Violation.INAPPLICABLE
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """206 with required headers"""
        if request.headers.get("Range"):
            return 206, [("etag", "abc")], "<div>ABC</div>"
        else:
            return 200, [("etag", "abc")], "<div>ABC</div>"

    def invalid(self, request, response):
        """206 without required headers"""
        if request.headers.get("Range"):
            return 206, [], "<div>ABC</div>"
        else:
            return 200, [("etag", "abc")], "<div>ABC</div>"


class code_304_headers:
    title = """
    304 NOT MODIFIED: same headers as 200
    """
    description = """
    The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request.
    """
    type = Level.REQUIREMENT
    category = "Statuscodes"
    source = "https://www.rfc-editor.org/rfc/rfc9110#name-304-not-modified"
    name = sys._getframe().f_code.co_name
    activity = Activity.RETRO

    def test(self, req_resps: list[ReqResp], url: Url) -> RetroTest:
        """If a conditional request receives 304, check for required headers (if they occur in a non-conditional request that receives 200)"""
        violation = set("ina")
        extra = ""
        headers_missing = set()
        c_rs = req_resps.where(
            ReqResp.req_type == "proxy-probe",
            ReqResp.probe_id.regexp("\\(\\d+, [4567], \\d+\\)"),
        )
        for c_r in c_rs:
            if c_r.resp_code == "'304'":
                probe_id = re.sub(
                    "\\((\\d+), (\\d+), (\\d+)\\)", "(\\1, 1, \\3)", c_r.probe_id
                )
                n_r = req_resps.where(ReqResp.probe_id == probe_id)[0]
                if n_r.resp_code == "'200'":
                    violation.add("val")
                    c_headers = parse_headers(c_r.resp_headers)
                    n_headers = parse_headers(n_r.resp_headers)
                    required_headers = set(
                        [
                            "date",
                            "cache-control",
                            "etag",
                            "expires",
                            "content-location",
                            "vary",
                        ]
                    )
                    missing_headers = required_headers - set(
                        [h.lower() for h in c_headers.keys(multi=False)]
                    )
                    missing_headers_get = missing_headers - set(
                        [h.lower() for h in n_headers.keys(multi=False)]
                    )
                    if missing_headers and missing_headers != missing_headers_get:
                        violation.add("inv")
                        headers_missing = headers_missing | missing_headers
        if headers_missing:
            extra += f"Headers missing for 304: {sorted(headers_missing)}"
        if "inv" in violation:
            v = Violation.INVALID
        elif "val" in violation:
            v = Violation.VALID
        else:
            v = Violation.INAPPLICABLE
        RetroTest.create(
            url=url, name=self.name, type=self.type, violation=v, extra=extra
        )

    def valid(self, request, response):
        """Return 304 with same headers to conditional request"""
        if request.headers.get("If-Match"):
            return 304, [("etag", "abc")], "<div>ABC</div>"
        return 200, [("etag", "abc")], "<div>ABC</div>"

    def invalid(self, request, response):
        """Return 304 with different headers to conditional request"""
        if request.headers.get("If-Match"):
            return 304, [], "<div>ABC</div>"
        return 200, [("etag", "abc")], "<div>ABC</div>"
