import json

from .db_util import ReqResp, RedTest, db, Url
from subprocess import check_output, CalledProcessError


class RedbotRequestor:
    """Class to run REDbot on a given URL."""
    def __init__(self, proxy=None, db_name="db/results_red.db", initial=False):
        self.db = db
        self.db.init(db_name)
        self.db.connect()
        if initial:
            self.db.create_tables([ReqResp, RedTest])

    def run(
        self,
        url: Url,
        timeout=2,
        method="GET",
        headers=None,
        data="",
        insecure=False,
        http2=False,
    ):
        try:
            with open("logs/redbot-err.log", "a") as f:
                o = check_output(
                    ["python", "bin/redbot_cli", "-a", "-o", "har", url.full_url],
                    cwd="redbot",
                    stderr=f,
                )
            o = json.loads(o)
            for test_results in o["log"]["entries"]:
                request = test_results["request"]
                real_url = request["url"]
                req_method = request["method"]
                req_version = request["httpVersion"]
                req_headers = request["headers"]

                response = test_results["response"]
                resp_version = response["httpVersion"]
                resp_code = response["status"]
                resp_headers = response["headers"]
                resp_body = response["content"]

                req_resp = ReqResp(
                    url=url,
                    real_url=real_url,
                    req_type="Redbot",
                    req_method=req_method,
                    req_version=req_version,
                    req_headers=req_headers,
                    resp_code=resp_code,
                    resp_version=resp_version,
                    resp_headers=resp_headers,
                    resp_body=resp_body,
                )
                req_resp.save()

                notes = test_results["_red_messages"]
                for note in notes:
                    name = note["note_id"]
                    subject = note["subject"]
                    category = note["category"]
                    violation = note["level"]
                    extra = note["summary"]
                    extra2 = note["text"]
                    red_test = RedTest(
                        url=url,
                        name=name,
                        subject=subject,
                        category=category,
                        violation=violation,
                        extra=extra,
                        extra2=extra2,
                        req=req_resp,
                    )
                    red_test.save()
        except CalledProcessError as e:
            req_resp = ReqResp(
                url=url, real_url=real_url.full_url, req_type="Redbot-failed"
            )
            req_resp.save()
            print(f"Redbot failed: {e}")

    def close(self):
        self.db.close()
