import inspect
import sys
import subprocess
import time
import traceback

# append the path of the parent directory
sys.path.append("..")
import testcases
from helpers.requestors import HttpxRequestor
from helpers.db_util import (
    Activity,
    setup_db,
    db,
    Site,
    Url,
    DirectTest,
    ProbeTest,
    RetroTest,
    AddResp,
    ReqResp,
)
from helpers.util import probes
from playhouse.shortcuts import model_to_dict
from dotenv import load_dotenv

load_dotenv()


def main(requestor):
    """Run all failing/passing responses for each test."""
    db_name = "sanity_check"
    try:
        setup_db(db_name)

        db.init(db_name)
        db.connect()
        db.create_tables(
            [Site, Url, DirectTest, ProbeTest, RetroTest, AddResp, ReqResp]
        )
        p = subprocess.Popen(
            [
                "poetry",
                "run",
                "mitmdump",
                "-s",
                "conformance_checker.py",
                "--set",
                "validate_inbound_headers=false",
                "--set",
                "ssl_insecure=true",
                "--set",
                f"db_name={db_name}",
            ],
            cwd="..",
        )
        time.sleep(5)

        PROXIES = {"all://": "http://localhost:8080"}
        requestor = requestor(PROXIES, set())

        site = Site.get_or_create(
            site_type="debug", description="sanity_check", rank=-1, site="localhost", bucket=-1, origin="localhost"
        )[0]
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
                obj = obj()
                # Run proxy test with valid/invalid server example
                if obj.activity == Activity.PROXY:
                    if obj.category == "HTTP/2" or obj.name in ["STS_header_after_upgrade_insecure_requests", "code_304_no_content", "transfer_encoding_http11"]:
                        base = "https://leaking.via:44333"
                        http2 = True
                        scheme = "https"
                        port = 44333
                    else:
                        base = "http://leaking.via:5001"
                        http2 = False
                        scheme = "http"
                        port = 5001
                    host = "leaking.via"
                    for val in ["valid", "invalid"]:
                        path = f"/{name}/{val}"
                        full_url = f"{base}{path}"
                        url = Url.get_or_create(
                            site=site,
                            full_url=full_url,
                            scheme=scheme,
                            host=host,
                            port=port,
                            path=path,
                            description="",
                            is_base=True,
                        )[0]
                        if obj.name == "post_invalid_response_codes":
                            method = "POST"
                        else:
                            method = "GET"
                        if obj.name == "close_option_in_final_response":
                            headers = {"connection": "close"}
                        else:
                            headers = {"upgrade-insecure-requests": "1"}
                        requestor.run(
                            f"{full_url}?url_id={url}",
                            method = method,
                            timeout=2,
                            verify=False,
                            http2=http2,
                            headers=headers
                        )

                # Run direct test with valid/invalid example
                if obj.activity in [Activity.DIRECT, Activity.DIRECT_BASE]:
                    base = "http://leaking.via:5001"

                    for url in [f"{base}/{name}/valid", f"{base}/{name}/invalid"]:
                        scheme, o = url.split("://")
                        host, o = o.split(":")
                        port, path = o.split("/", maxsplit=1)
                        port = int(port)
                        path = f"/{path}"
                        url = Url.get_or_create(
                            site=site,
                            full_url=url,
                            scheme=scheme,
                            host=host,
                            port=port,
                            path=path,
                            description="",
                            is_base=True,
                        )[0]

                        try:
                            res = obj.test(url)
                        except Exception as e:
                            DirectTest.create(
                                url=url, name=name, type=obj.type, test_error=e
                            )
                            print(f"{name} failed: {e}")
                            res = None
                        if res != None:
                            r_d = model_to_dict(res)
                            print(f"{url.path}: {r_d['violation'], r_d['extra']}\n")

                # Run retro tests: first run all probes for both valid/invalid URL, then run the retro test
                if obj.activity == Activity.RETRO:
                    base = "http://leaking.via:5001"

                    for url in [f"{base}/{name}/valid", f"{base}/{name}/invalid"]:
                        scheme, o = url.split("://")
                        host, o = o.split(":")
                        port, path = o.split("/", maxsplit=1)
                        port = int(port)
                        path = f"/{path}"
                        url = Url.get_or_create(
                            site=site,
                            full_url=url,
                            scheme=scheme,
                            host=host,
                            port=port,
                            path=path,
                            description="",
                            is_base=True,
                        )[0]
                        for probe_id, (method, headers, http2) in probes.items():
                            if http2:
                                continue
                            requestor.run(
                                f"{url.full_url}?url_id={url}&probe_id={probe_id}",
                                method=method,
                                headers=headers,
                                timeout=5,
                                verify=False,
                                http2=http2,
                            )

                        try:
                            req_resps = ReqResp.select().where(ReqResp.url == url)
                            res = obj.test(req_resps, url)
                        except Exception as e:
                            RetroTest.create(
                                url=url, name=name, type=obj.type, test_error=e
                            )
                            print(f"{name} failed: {e}")
                            res = None
                        if res != None:
                            r_d = model_to_dict(res)
                            print(f"{url.path}: {r_d['violation'], r_d['extra']}\n")

    except Exception as e:
        print(traceback.format_exc())
        print(e)
    finally:
        db.close()
        p.terminate()
        requestor.close()


if __name__ == "__main__":
    main(HttpxRequestor)
