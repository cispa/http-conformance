import httpx


class HttpxRequestor:
    """Class to run HTTPX on a given URL."""
    def __init__(self, proxy, error_set):
        self.proxy = proxy
        self.error_set = error_set

    def run(
        self,
        url,
        params={},
        timeout=2,
        method="GET",
        headers=None,
        data="",
        verify=True,
        http2=False,
    ):
        status = r_headers = body = error = version = ""
        try:
            if http2:
                client = httpx.Client(http2=True, proxies=self.proxy, verify=verify)
                r = client.request(
                    method=method,
                    url=url,
                    params=params,
                    timeout=timeout,
                    headers=headers,
                    content=data,
                    follow_redirects=False,
                )
            else:
                r = httpx.request(
                    method=method,
                    url=url,
                    params=params,
                    proxies=self.proxy,
                    timeout=timeout,
                    headers=headers,
                    content=data,
                    follow_redirects=False,
                    verify=verify,
                )
            status = r.status_code
            r_headers = r.headers
            body = r.content.decode("utf-8", errors="replace").replace("\x00", "")
            version = r.http_version
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            error = e
        except Exception as e:
            if not repr(e) in self.error_set:
                print(f"{method} {url}: {e} -Headers: {headers}")
                self.error_set.add(repr(e))
            error = e
        return (status, r_headers, body, version, error)

    def close(self):
        return self.error_set
