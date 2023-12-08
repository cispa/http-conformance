from typing import Union, Tuple

import re
import socket
import ssl
import dpkt

from .db_util import Req, Url, DirectTest, ReqResp, AddResp


def connect_h1_socket(host, port=443, https=False, timeout=1):
    """Create a socket and connect to it HTTP1 with or wihout TLS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if https:
        sock.connect((host, port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)
    else:
        sock.connect((host, port))
    return sock


def send_all(s, req):
    """Send all req bytes oven socket s."""
    sent = 0
    while sent < len(req):
        sent = sent + s.send(req[sent:])


def recv_all(s):
    """Receive all bytes on socket s."""
    response = b""
    try:
        while True:
            chunk = s.recv(4096)
            if len(chunk) == 0:  # No more data received, quitting
                break
            response = response + chunk
    except socket.timeout as e:
        pass
    finally:
        return response


def parse_response(response, head_response=False):
    """Parse HTTP responses from socket bytes using dpkt."""
    # If several responses are received split them (in theory this sequence could be in the body of a response!)
    responses = re.split(rb"(?<=\r\n\r\n)(?=HTTP/)", response)

    r = []
    # dpkt throws parse errors for incorrect responses (only some, parsing not very strict, e.g., space between header name and colon allowed)
    for response in responses:
        try:
            # Needs patched version of dpkt! (change http.py: 1. add **kwargs to L103, L232, L178), 2. add head_response=False to L232, 3. add if head_response: is_body_allowed = False to L252)
            h_resp = dpkt.http.Response(response, head_response=head_response)
            h_resp = (h_resp, response)
        except Exception as e:
            h_resp = (e, response)
        finally:
            r.append(h_resp)
    return r


def build_request(
    host,
    port,
    method=b"GET",
    request_target=b"/",
    http_version=b"HTTP/1.1",
    line_end=b"\r\n",
    request_line=None,
    host_header=None,
    accept_header=b"Accept: */*\r\n",
    accept_encoding_header=b"Accept-Encoding: gzip, deflate, br\r\n",
    connection_header=b"Connection: keep-alive\r\n",
    ua_header=b"User-Agent: test\r\n",
    cc_header=b"Cache-Control: no-store\r\n",
    headers=None,
    additional_headers=b"",
    header_end=b"\r\n",
    body=b"",
) -> Req:
    """Create a request."""
    if request_line is None:
        if type(request_target) == str:
            request_target = request_target.encode("utf-8")
        request_line = b" ".join([method, request_target, http_version]) + line_end

    if headers is None:
        headers = b""
        if host_header is None:
            # Include non default ports
            if port not in [443, 80]:
                host_header = (
                    b"Host: "
                    + host.encode("utf-8")
                    + b":"
                    + str(port).encode("utf-8")
                    + b"\r\n"
                )
            # Do not include ports for default ports
            # (Testing differences with/out port might be intresting as well as host not as the first header?!)
            else:
                host_header = b"Host: " + host.encode("utf-8") + b"\r\n"
        headers = (
            host_header
            + accept_header
            + accept_encoding_header
            + cc_header
            + ua_header
            + connection_header
            + additional_headers
            + header_end
        )
    # Postgres Issue: cannot save \x00 in text columns :( https://www.commandprompt.com/blog/null-characters-workarounds-arent-good-enough/
    req = Req(
        req_method=method.decode("utf-8", errors="surrogateescape"),
        req_version=http_version.decode("utf-8", errors="surrogateescape"),
        req_headers=headers.decode("utf-8", errors="surrogateescape"),
        req_body=body.decode("utf-8", errors="surrogateescape"),
        req_raw=request_line + headers + body,
        req_path=request_target.decode("utf-8", errors="surrogateescape"),
    )
    return req


def one_req(url: Url, dt: DirectTest, req: Req, head_response=False):
    """Send one request and parse the response."""
    https = True if url.scheme == "https" else False
    s = connect_h1_socket(url.host, port=url.port, https=https)
    send_all(s, req.req_raw)
    raw_response = recv_all(s)
    responses = parse_response(raw_response, head_response=head_response)
    s.close()
    real_url = f"{url.scheme}://{url.host}{':' + str(url.port) if url.port not in [80, 443] else ''}{req.req_path}"
    f_resp, _ = responses[0]
    if type(f_resp) != dpkt.http.Response:
        r = ReqResp.create(
            url=url,
            direct_test=dt,
            real_url=real_url,
            msg=f_resp,
            req_type="socket",
            req_method=req.req_method,
            req_version=req.req_version,
            req_headers=req.req_headers,
            req_body=req.req_body,
            req_raw=req.req_raw,
            resp_raw=raw_response,
        )
    else:
        r = ReqResp.create(
            url=url,
            direct_test=dt,
            real_url=real_url,
            req_type="socket",
            req_method=req.req_method,
            req_version=req.req_version,
            req_headers=req.req_headers,
            req_body=req.req_body,
            req_raw=req.req_raw,
            resp_code=f_resp.status,
            resp_version=f"HTTP/{f_resp.version}",
            resp_headers=list(f_resp.headers.items()),
            resp_body=f_resp.body.decode("utf-8", errors="surrogateescape"),
            resp_add_data=f_resp.data.decode("utf-8", errors="surrogateescape"),
            resp_raw=raw_response,
        )

    for resp, resp_raw in responses[1:]:
        if type(resp) != dpkt.http.Response:
            AddResp.create(req=r, msg=resp, resp_raw=resp_raw)
        else:
            AddResp.create(
                req=r,
                resp_code=resp.status,
                resp_version=f"HTTP/{f_resp.version}",
                resp_headers=list(resp.headers.items()),
                resp_body=resp.body.decode("utf-8", errors="surrogateescape"),
                resp_add_data=resp.data.decode("utf-8", errors="surrogateescape"),
                resp_raw=resp_raw,
            )
    return responses


def get_codes(
    responses: list[Tuple[Union[dpkt.http.Response, dpkt.UnpackError], bytes]]
) -> list[str]:
    """Extract the HTTP StatusCodes from a list of dpkt responses."""
    codes = []
    for resp, _ in responses:
        if type(resp) == dpkt.UnpackError:
            codes.append(resp)
        else:
            codes.append(resp.status)
    return codes
