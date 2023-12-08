import inspect

from wpt.tools.wptserve.wptserve import server as wptserve
from wpt.tools.wptserve.wptserve.handlers import FunctionHandler

import sys

# append the path of the parent directory
sys.path.append("..")
import testcases

h1_port = 5001
h2_port = 44333
http1 = wptserve.WebTestHttpd(
    port=h1_port,
    routes=None,
    use_ssl=False,
    key_file=None,
    certificate=None,
)

https2 = wptserve.WebTestHttpd(
    port=h2_port,
    handler_cls=wptserve.Http2WebTestRequestHandler,
    routes=None,
    use_ssl=True,
    key_file="certs/key.pem",
    certificate="certs/cert.pem",
    encrypt_after_connect=False,
    http2=True,
)

if __name__ == "__main__":
    """Serve all demo responses (valid/invalid) in HTTP1 and HTTP2"""
    http1.start()
    https2.start()

    # Add all testcases with correct URLs
    for name, obj in inspect.getmembers(testcases):
        if inspect.isclass(obj) and name not in [
            "StrEnum",
            "Activity",
            "Violation",
            "Level",
            "datetime",
            "DirectTest",
            "ProbeTest",
            "RetroTest",
            "ReqResp",
            "Url",
        ]:
            testclass = obj()
            http1.router.register(
                "*", f"/{name}/valid", FunctionHandler(testclass.valid)
            )
            http1.router.register(
                "*", f"/{name}/invalid", FunctionHandler(testclass.invalid)
            )

            https2.router.register(
                "*", f"/{name}/valid", FunctionHandler(testclass.valid)
            )
            https2.router.register(
                "*", f"/{name}/invalid", FunctionHandler(testclass.invalid)
            )
    print(f"Started HTTP1 test server on {h1_port}, HTTP2 test server on {h2_port}. Stop with CTRL+C.")
    from threading import Event

    Event().wait()
