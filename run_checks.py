from datetime import date
from functools import partial
import socket
import time
import os
import subprocess
import inspect
import traceback
import httpx
import argparse

from tqdm import tqdm
from dotenv import load_dotenv
from multiprocessing import Pool, current_process
from helpers.requestors import HttpxRequestor
from helpers.redbot_requestor import RedbotRequestor
from helpers.util import create_sites_urls, report_error, probes
from helpers.db_util import (
    db,
    Site,
    Url,
    setup_db,
    Activity,
    DirectTest,
    ProbeTest,
    RetroTest,
    AddResp,
    ReqResp,
    Monitoring,
)
import testcases

load_dotenv()
mitmcert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca.pem")

def run_tests(
    test_url: Url,
    site_source: str,
    redbot: RedbotRequestor,
    requestor: HttpxRequestor,
    direct_tests: list[DirectTest],
    direct_base_tests: list[DirectTest],
    retro_tests: list[RetroTest],
    error_set: set,
    probe_sleep=2,
    direct_sleep=5,
):
    """Run all tests for a given URL.
    Only run direct tests if site_source==local.
    Only run tests if an initial basic request to the URL succeeds.
    """
    # Perform a valid/normal GET request and only test URL if that worked + save response (status code and similar)
    # Follow redirects to check that a valid page can get reached
    try:
        r: httpx.Response = httpx.request(
            method="GET",
            url=test_url.full_url,
            timeout=30,
            verify=False,
            follow_redirects=True,
        )
        status = r.status_code
        r_headers = r.headers
        body = r.content.decode("utf-8", errors="replace").replace("\x00", "")
        version = r.http_version
        error = None
    except httpx.TimeoutException as e:
        error = e
    except Exception as e:
        error = e
    finally:
        if error:
            m: Monitoring = Monitoring.create(url=test_url, b_error=error, susp="NA")
            return error_set
        else:
            m: Monitoring = Monitoring.create(
                url=test_url,
                b_resp_code=status,
                b_resp_headers=r_headers,
                b_resp_body=body,
                b_resp_version=version,
            )

    # Ratelimiting: sleep between each request >1s
    # Redbot crashes on Linux (for http requests) see https://github.com/mnot/redbot/issues/305
    # Only run for https URLs (they can also crash, but only very rarely)
    if test_url.scheme == "https":
        try:
            redbot.run(test_url)
        except Exception as e:
            req_resp = ReqResp(
                url=test_url, real_url=test_url.full_url, req_type="Redbot-failed"
            )
            req_resp.save()
            print(f"Redbot failed for: {test_url}, {e}")

    # Run passive/proxy tests
    # Trust mitmproxy cert; real TLS check performed by mitmproxy (currently ignore TLS errors)
    for probe_id, (method, headers, http2) in probes.items():
        # Skip "dangerous" probes for non-local modes (i.e., delete)
        if site_source != "local" and (method == "DELETE"):
            continue
        params = {"url_id": str(test_url.id), "probe_id": str(probe_id)}
        status, r_headers, body, version, error = requestor.run(
            test_url.full_url,
            params=params,
            method=method,
            headers=headers,
            timeout=30,
            verify=mitmcert_path,
            http2=http2,
        )
        if error != "":
            ReqResp.create(
                url=test_url,
                real_url=test_url.full_url,
                probe_id=probe_id,
                error=error,
                req_type="proxy-probe-failed",
                req_method=method,
                req_version="HTTP/2" if http2 else "HTTP/1.1",
                req_headers=headers,
                resp_code=status,
                resp_version=version,
                resp_headers=r_headers,
                resp_body=body,
            )
        time.sleep(probe_sleep)

    # Run direct tests (local only)
    if site_source == "local":
        for test in direct_tests:
            try:
                test.test(test_url)
                time.sleep(direct_sleep)
            except Exception as e:
                DirectTest.create(
                    url=test_url, name=test.name, type=test.type, test_error=e
                )
                if not repr(e) in error_set:
                    print(f"{test_url.full_url}-{test.name} failed: {e}")
                    error_set.add(repr(e))

        # Run direct_base tests
        # Only run these tests for the base_urls!
        if test_url.is_base:
            for test in direct_base_tests:
                try:
                    test.test(test_url)
                    time.sleep(direct_sleep)
                except Exception as e:
                    DirectTest.create(
                        url=test_url, name=test.name, type=test.type, test_error=e
                    )
                    if not repr(e) in error_set:
                        print(f"{test_url.full_url}-{test.name} failed: {e}")
                        error_set.add(repr(e))

    # Run retro tests on resulting data
    req_resps = ReqResp.select().where(ReqResp.url == test_url)
    for test in retro_tests:
        try:
            test.test(req_resps, test_url)
        except Exception as e:
            RetroTest.create(url=test_url, name=test.name, type=test.type, test_error=e)
            if not repr(e) in error_set:
                print(f"{test_url.full_url}-{test.name} failed: {e}")
                error_set.add(repr(e))

    # Perform final normal/valid GET request to URL (up to 3x for timeout issues) and compare with first GET request
    # If request fails or result is not the same as for the first GET request alert/monitor
    n = 1
    error = None
    while n <= 3:
        try:
            r = httpx.request(
                method="GET",
                url=test_url.full_url,
                timeout=30,
                verify=False,
                follow_redirects=True,
            )
            status = r.status_code
            r_headers = r.headers
            body = r.content.decode("utf-8", errors="replace").replace("\x00", "")
            version = r.http_version
            break
        except httpx.TimeoutException as e:
            error = e
            n += 1
        except Exception as e:
            error = e
            break

    if error:
        m.a_error = error
        m.susp = "Error"
    else:
        m.a_resp_code = status
        m.a_resp_headers = r_headers
        m.a_resp_body = body
        m.a_resp_version = version
        if m.a_resp_code != m.b_resp_code:
            m.susp = "Code"
            # Ignore 429 rate-limiting for reporting (430 spotify custom rate-limit)
            if not m.a_resp_code in [429, 430]:
                pass

    m.a_rep = n
    m.save()

    return error_set


def run_site(
    site_source: str,
    db_name: str,
    log_id: str,
    direct_tests: list[DirectTest],
    direct_base_tests: list[DirectTest],
    retro_tests: list[RetroTest],
    site: Site,
    delay=10,
):
    """Run all tests for all URLs belonging to a site."""
    global error_set
    num = int(current_process().name.split("-")[1])
    port = 15000 + num

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("localhost", port)) == 0:
            return f"Port: {port} already used; abort; site: {site.description}!"
    try:
        db.init(db_name)
        db_connected = db.connect()
        site.status = "Testing"
        site.save()
        # Start mitmproxy
        logfile = open(f"logs/mitmdump_{log_id}_{port}.log", "a")
        p = subprocess.Popen(
            [
                "poetry",
                "run",
                "mitmdump",
                "-s",
                "conformance_checker.py",
                "-p",
                f"{port}",
                "--set",
                "validate_inbound_headers=false",
                "--set",
                "ssl_insecure=true",
                "--set",
                f"db_name={db_name}",
            ],
            stdout=logfile,
            stderr=logfile,
        )
        time.sleep(5)

        requestor = HttpxRequestor(
            proxy={"all://": f"http://localhost:{port}"}, error_set=error_set
        )
        redbot = RedbotRequestor(db_name=db_name)

        urls = Url.select().where(Url.site == site)
        for url in urls:
            error_set.update(
                run_tests(
                    url,
                    site_source,
                    redbot,
                    requestor,
                    direct_tests,
                    direct_base_tests,
                    retro_tests,
                    error_set,
                )
            )
            # Extra delay between each URL of a site
            time.sleep(delay)
    except Exception as e:
        print(f"Process {num} crashed {e}: {traceback.format_exc()}")
    finally:
        try:
            site.status = "Finished"
            site.save()
            p.terminate() if "p" in locals() else print(
                f"Process {num}: Mitmdump process does not exist"
            )
            db.close() if "db_connected" in locals() else print(
                f"Process {num}: db does not exist"
            )
            redbot.close() if "redbot" in locals() else print(
                f"Process {num}: redbot does not exist"
            )
            error_set.update(requestor.close()) if "requestor" in locals() else print(
                f"Process {num}: requestor does not exist"
            )
            logfile.close() if "logfile" in locals() else print(
                f"Process {num}: logfile does not exist"
            )
            # Make sure everything closed correctly!
            time.sleep(5)
        except Exception as e:
            print(
                f"########\nMajor fail in process {num}: {e};{traceback.format_exc()}\n#############"
            )


def setup_process():
    """Setup of each process with delay"""
    global error_set
    error_set = set()
    num = int(current_process().name.split("-")[1])
    # Slowly start all processes, one new every second
    time.sleep(num * 1)
    print(f"Started process: {num}")


def main(site_source, max_workers):
    """Run all tests for all sites with min(max_workers, len(sites)) processes."""
    log_id = f"{site_source}_{date.today().strftime('%Y_%m_%d')}"
    db_name = f"results_{log_id}"
    try:
        setup_db(db_name)

        db.init(db_name)
        db.connect()
        db.create_tables(
            [Site, Url, DirectTest, ProbeTest, RetroTest, AddResp, ReqResp, Monitoring]
        )

        redbot = RedbotRequestor(db_name=db_name, initial=True)
        redbot.close()

        # Test Top5k + 5k out of long tail (popularity between 500 000 and 1 000 000)
        create_sites_urls(
            db_name,
            recreate=False,
            site_type=site_source,
            buckets=[(1000, 1000), (5000, 4000), (1000000, 5000)],
        )
        direct_tests = []
        direct_base_tests = []
        retro_tests = []

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
                if obj.activity == Activity.DIRECT:
                    direct_tests.append(obj)
                elif obj.activity == Activity.DIRECT_BASE:
                    direct_base_tests.append(obj)
                elif obj.activity == Activity.RETRO:
                    retro_tests.append(obj)

        # Number of probe requests
        print(f"Number of probes: {len(probes)}")

        # Maximum number of processes: number of sites or max_workers
        # Ensures no parallel requests to a site exist
        sites = Site.select().where(Site.site_type == site_source)
        max_workers = min(len(sites), max_workers)
        print(f"Number of workers: {max_workers}")
        report_error(f"Starting experiment: {db_name}, workers={max_workers}.")

        # Run in parallel
        run_task = partial(
            run_site,
            site_source,
            db_name,
            log_id,
            direct_tests,
            direct_base_tests,
            retro_tests,
        )
        with Pool(max_workers, initializer=setup_process) as p:
            r = list(
                tqdm(
                    p.imap(run_task, sites), leave=True, desc="Sites", total=len(sites)
                )
            )
        print(r)

    except Exception as e:
        print(e)
        print(traceback.format_exc())
    finally:
        db.close()
        report_error(f"Finished experiment: {db_name}, workers={max_workers}.")


if __name__ == "__main__":
    available_modes = ["local", "popular"]
    # Create an argument parser
    parser = argparse.ArgumentParser(description="Run HTTP Conformance Testing on either local or popular sites.")
    # Add a command-line option for the mode
    parser.add_argument("--mode", choices=available_modes, help="Select the mode: local or popular")
    # Add a command-line option for max-workers
    parser.add_argument("--max_workers", type=int, default=300, help="Specify the maximum number of processes")
    # Parse the command-line arguments
    args = parser.parse_args()
    # Access the selected mode using args.mode
    selected_mode = args.mode

    report_error(f"Starting {selected_mode}")
    main(selected_mode, max_workers=args.max_workers)
    time.sleep(5)
