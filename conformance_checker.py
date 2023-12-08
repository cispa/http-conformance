from mitmproxy import http, log, ctx
import inspect
import testcases
from helpers.db_util import Activity, db, ReqResp, ProbeTest, DirectTest, Violation


class ConformanceChecker:
    """MITMProxy Addon to run all ProbeTests on received responses."""
    def __init__(self) -> None:
        pass

    def load(self, loader) -> None:
        loader.add_option(
            name="db_name",
            typespec=str,
            default="",
            help="Specify DB Name",
        )

    def running(self) -> None:
        self.db = db
        self.db.init(ctx.options.db_name)
        self.db.connect()
        self.db.create_tables([ReqResp, ProbeTest, DirectTest])
        self.msg = ""

    def done(self):
        self.db.close()

    def request(self, flow: http.HTTPFlow) -> None:
        """Remove url_id and probe_id from the URL (we only need it to identify the requets internally)."""
        flow.url_id = None
        flow.probe_id = None
        try:
            flow.url_id = flow.request.query["url_id"]
            del flow.request.query["url_id"]
            flow.probe_id = flow.request.query["probe_id"]
            del flow.request.query["probe_id"]
        except KeyError:
            pass

    def response(self, flow: http.HTTPFlow) -> None:
        """Run all ProbeTests on received responses."""
        # We cannot test CONNECT functionality with mitmproxy, receiving a CONNECT response means we hit an internal response of mitmproxy
        # These might have evaded the request function and thus, do not need to have a url_id!
        req_method = flow.request.method
        if req_method == "CONNECT":
            return

        url = flow.request.url
        site = f"{flow.request.host}:{flow.request.port}"
        req_version = flow.request.http_version
        req_headers = flow.request.headers.fields
        req_body = flow.request.get_text(strict=False)

        resp_code = str(flow.response.status_code)
        resp_version = flow.response.http_version
        resp_headers = flow.response.headers.fields
        resp_body = flow.response.get_text(strict=False)

        req_resp = ReqResp.create(
            url=flow.url_id,
            real_url=url,
            probe_id=flow.probe_id,
            msg=self.msg,
            req_type="proxy-probe",
            req_method=req_method,
            req_version=req_version,
            req_headers=req_headers,
            req_body=req_body,
            resp_code=resp_code,
            resp_version=resp_version,
            resp_headers=resp_headers,
            resp_body=resp_body,
        )

        self.msg = ""

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
                # Only run the proxy tests!
                if testclass.activity == Activity.PROXY:
                    try:
                        result = testclass.test(flow)
                        if result is None:
                            result = ProbeTest()
                    except Exception as e:
                        result = ProbeTest(
                            name=name,
                            test_error=e,
                            type=testclass.type,
                            violation=Violation.FAILED,
                        )
                        print(f"{name} failed: {e}")
                    finally:
                        result.req = req_resp
                        result.url = flow.url_id
                        # Do not save data for inapplicable tests (otherwise there will be too many entries in the db)
                        if result.type != "" or result.test_error != "":
                            if result.violation != Violation.INAPPLICABLE:
                                result.save()

    def error(self, flow: http.HTTPFlow) -> None:
        """Log MITMProxy errors: e.g., invalid content-length header value "abc"."""
        url = flow.request.url
        site = f"{flow.request.host}:{flow.request.port}"
        req_version = flow.request.http_version
        req_method = flow.request.method
        req_headers = flow.request.headers.fields
        req_body = flow.request.get_text(strict=False)
        try:
            url_id = flow.url_id
        except AttributeError:
            url_id = None
        try:
            probe_id = flow.probe_id
        except AttributeError:
            probe_id = None

        req_resp = ReqResp.create(
            url=url_id,
            real_url=url,
            probe_id=probe_id,
            error=flow.error,
            msg=self.msg,
            req_type="proxy-probe-error",
            req_method=req_method,
            req_version=req_version,
            req_headers=req_headers,
            req_body=req_body,
        )
        self.msg = ""
        print(f"Request to {url} failed {flow.error}")

    def add_log(self, entry: log.LogEntry) -> None:
        """
        Log other errors, e.g., "Unexpected data from server" when data is send after head!
        As long as we have no parallel connections, we know that the data belongs to the next request or the previous request.
        The error occurs before the response function is called
        """
        if "Unexpected" in entry.msg:
            self.msg = entry.msg
        elif "Swallowing" in entry.msg:
            self.msg = entry.msg
        else:
            pass


addons = [
    ConformanceChecker(),
]
