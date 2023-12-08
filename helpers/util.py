from ast import literal_eval
from datetime import datetime
from functools import partial
from multiprocessing.pool import ThreadPool
import random
import string
import httpx

import re
import os
import pandas as pd

from tld import get_fld
from tranco import Tranco
from mitmproxy.http import Headers

from datetime import datetime, timezone
from email.utils import format_datetime

from .db_util import Site, Url, db
from peewee import IntegrityError

# TODO: replace with (Mattermost) Webhook
WEB_HOOK = "TODO"

# TODO: replace user_agent with a link to your crawl information website with the option to opt-out
user_agent = "TODO"


def is_reachable(origin, timeout=10):
    """Check whether origin is reachable (no error and answer takes less than timeout/10s)."""
    reachable = True
    error = ""
    try:
        # Follow redirects (we only test hosts that return a valid page for a normal request/are not completely broken)
        httpx.get(origin + "/", timeout=timeout, follow_redirects=True)
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        reachable = False
        error = e
    except Exception as e:
        reachable = False
        print(f"Site error: {origin} - {e}")
        error = e
    finally:
        return reachable, error


def add_origin(t_list, site_type, bucket, origin):
    """Add new origin to the database (with both http and https) if reachable."""
    org_scheme, host = origin.split("://", maxsplit=1)
    for scheme, port in [("http", 80), ("https", 443)]:
        origin = f"{scheme}://{host}"
        reachable, error = is_reachable(origin)
        site = get_fld(origin)
        rank = t_list.rank(site)
        try:
            s = Site.create(
                site_type=site_type,
                description=origin,
                rank=rank,
                site=site,
                reachable=reachable,
                error=error,
                bucket=bucket,
                origin=origin,
                org_scheme=org_scheme,
            )
            s.save()
        except IntegrityError:
            print(f"{origin} already exist!")
            continue
        if not reachable:
            continue

        full_url = f"{origin}/"
        for full_url, path, desc in get_test_urls(full_url, "/", scheme):
            if path == "/":
                is_base = True
            else:
                is_base = False
            u = Url.create(
                site=s,
                full_url=full_url,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                description=desc,
                is_base=is_base,
            )
            u.save()


def create_sites_urls(
    db_name,
    recreate=False,
    site_type="local",
    buckets=[(1000, 1000), (10000, 1000), (100000, 1000), (1000000, 1000)],
    workers=300,
):
    """Buckets (bucket, n): first entry is the bucket, e.g, Top1K, second one is the number of origins to take from this bucket.
    Available buckets: 1000, 5000, 10000, 50000, 100000, 500000, 1000000

    Create Sites and URLs entries in the database.
    """
    db.init(db_name)
    db.connect()
    if len(Site.select()) != 0 and not recreate:
        return

    db.drop_tables([Site, Url], cascade=True)
    db.create_tables([Site, Url])

    t = Tranco(cache=True, cache_dir=".tranco")
    t_list = t.list(date="2023-01-30")

    # Local (HTTP and HTTPS counted as separated sites)
    if site_type == "local":
        local_file = f"{os.path.dirname(__file__)}/../testbed/.env"
        with open(local_file, "r") as f:
            local_file = f.read()
            matches = re.findall(
                "^(?!#)(.*)_(http|https)_port=(\d+)", local_file, re.MULTILINE
            )
            for site, scheme, port in matches:
                s = Site(
                    site_type=site_type,
                    description=f"{site}-{scheme}",
                    rank=-1,
                    site=site,
                    origin=f"{scheme}://{site}",
                    bucket=-1,
                )
                s.save()
                # For some of the local servers (caddy), the cert only works for localhost no IPs?
                host = "localhost"
                full_url = f"{scheme}://{host}:{port}/"
                for full_url, path, desc in get_test_urls(full_url, "/", scheme):
                    if path == "/":
                        is_base = True
                    else:
                        is_base = False
                    u = Url(
                        site=s,
                        full_url=full_url,
                        scheme=scheme,
                        host=host,
                        port=port,
                        path=path,
                        description=desc,
                        is_base=is_base,
                    )
                    u.save()

    # CrUX origins (HTTP and HTTPS together)
    elif site_type == "popular":
        df = pd.read_csv("helpers/202302.csv")
        for bucket, sample_size in buckets:
            origins = df.loc[df["rank"] == bucket].head(sample_size)
            with ThreadPool(workers) as pool:
                add_origin_f = partial(add_origin, t_list, site_type, bucket)
                pool.map(add_origin_f, origins["origin"])
    else:
        raise Exception(f"No valid type: {site_type}")


def random_string(length=32):
    """Generate a random string to be used in URL (/<rand>)."""
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(length)
    )


def get_test_urls(full_url, path, scheme, timeout=10):
    """Generate all test URLs from one URL (landing page)."""
    # Additional paths that should get tested
    urls = [(full_url, path, "Base URL")]
    random.seed(full_url)
    random_path = random_string(length=32)
    urls.append((f"{full_url}{random_path}", f"/{random_path}", "non-existing"))
    try:
        r_url = httpx.get(
            full_url, follow_redirects=True, timeout=timeout, verify=False
        ).url
        # Add non redirecting URL, if base URL redirects; Only if same-origin
        if full_url != r_url:
            if r_url.host == httpx.URL(full_url).host and r_url.scheme == scheme:
                urls.append((r_url, r_url.path, "non redirecting URL"))
                # print(r_url)
    except Exception as e:
        print(f"URL error: {full_url} - {e}")
    return urls


def parse_headers(header_s):
    """String to MITMProxy Header object."""
    return Headers(literal_eval(header_s))


def report_error(s):
    """Report message using MM hook."""
    print(s)
    n = 1
    while n <= 3:
        try:
            httpx.request(
                method="POST",
                url=WEB_HOOK,
                json={"text": s, "username": "HTTP testing"},
                timeout=30,
            )
            break
        except Exception as e:
            n += 1
            print(f"Mattermost Hook failed: {e}")


# All probes used to send PROBE requests
probes = {}
probe_methods = {
    1: "GET",
    2: "HEAD",
    3: "POST",
    4: "OPTIONS",
    5: "DELETE",
    6: "PUT",
    7: "TRACE",
    8: "PATCH",
    9: "ABC",
}

probe_headers = {
    1: {"user-agent": user_agent, "cache-control": "no-store"},
    2: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "upgrade-insecure-requests": "1",
    },
    3: {"user-agent": user_agent, "cache-control": "no-store", "Range": "bytes=0-10"},
    4: {"user-agent": user_agent, "cache-control": "no-store", "If-Match": "*"},
    5: {"user-agent": user_agent, "cache-control": "no-store", "If-None-Match": "*"},
    6: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "If-Modified-Since": format_datetime(datetime.now(timezone.utc), usegmt=True),
    },
    7: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "If-Range": format_datetime(datetime.now(timezone.utc), usegmt=True),
    },
    8: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "Early-Data": "1",
    },  # Valid early data
    9: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "Early-Data": "Abc",
    },  # Invalid early data
    10: {
        "user-agent": user_agent,
        "cache-control": "no-store",
        "Connection": "close",
    },  # Connection close (default of HTTPX is keep-alive)
}

probe_http2 = {
    1: False,  # HTTP/1.1
    2: True,  # HTTP/2
}

for m_i, method in probe_methods.items():
    for h_i, headers in probe_headers.items():
        for h2_i, h2 in probe_http2.items():
            probes[(m_i, h_i, h2_i)] = (method, headers, h2)
