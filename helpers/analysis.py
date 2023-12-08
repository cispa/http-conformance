import pandas as pd
from IPython.display import display
import matplotlib.pyplot as plt


def get_violations(db, redbot=False):
    """Return rows that break specifications."""
    dfs = {}
    if redbot:
        c = db.execute_sql(
            f"SELECT DISTINCT url_id, name, violation, subject, extra from redtest"
        )
        columns = [col.name for col in c.description]
        test_violations = pd.DataFrame(c.fetchall(), columns=columns)
        test_violations["test_type"] = "redbot"
    else:
        for test in ["directtest", "probetest", "retrotest"]:
            c = db.execute_sql(
                f"SELECT DISTINCT url_id, name, type from {test} where violation = 'Breaks specification'"
            )
            columns = [col.name for col in c.description]
            df = pd.DataFrame(c.fetchall(), columns=columns)
            dfs[test] = df
        test_violations = pd.DataFrame()
    for key, df in dfs.items():
        if "test" in key:
            df["test_type"] = key
            test_violations = pd.concat([test_violations, df])
    c = db.execute_sql(
        f"SELECT site.description, url.*, site.* from URL join site on url.site_id = site.id"
    )
    columns = [col.name for col in c.description]
    url_info = pd.DataFrame(c.fetchall(), columns=columns)
    url_info = url_info.loc[:, ~url_info.columns.duplicated()]
    return test_violations, url_info


def get_violation_details(db, test_name, limit=1000):
    """Return all details for violating tests for manual analysis."""
    c = db.execute_sql(
        "select * from (Select distinct on (url_id) * from probetest where name = %s and violation = 'Breaks specification' LIMIT %s) as probe JOIN reqresp ON probe.req_id = reqresp.id JOIN url ON probe.url_id = url.id",
        (
            test_name,
            limit,
        ),
    )
    columns = [col.name for col in c.description]
    return pd.DataFrame(c.fetchall(), columns=columns)


def get_resp_details(db, sites):
    """Return all data for a group of sites."""
    c = db.execute_sql(
        """SELECT site.*, url.*, reqresp.*
FROM site
JOIN url ON url.site_id = site.id
JOIN reqresp ON reqresp.url_id = url.id
WHERE (site.site, site.id, reqresp.id) IN (
    SELECT site.site, MIN(site.id), MIN(reqresp.id) AS min_reqresp_id
    FROM site
    JOIN url ON url.site_id = site.id
    JOIN reqresp ON reqresp.url_id = url.id
    where site = ANY(%s)
    GROUP BY site.site
);""",
        (sites,),
    )
    columns = [col.name for col in c.description]
    return pd.DataFrame(c.fetchall(), columns=columns)


def get_direct_details(db, test_name, limit=1000):
    """Return detailed db entries for a direct test."""
    c = db.execute_sql(
        "select * from (Select * from directtest where name = %s and violation = 'Breaks specification' LIMIT %s) as dt JOIN reqresp ON dt.id = reqresp.direct_test_id JOIN url ON dt.url_id = url.id",
        (
            test_name,
            limit,
        ),
    )
    columns = [col.name for col in c.description]
    df = pd.DataFrame(c.fetchall(), columns=columns)
    d = {"id": ["dt_id", "req_id", "url_id"]}
    df = df.rename(columns=lambda c: d[c].pop(0) if c in d.keys() else c)
    df["req_raw"] = df["req_raw"].apply(lambda x: b"".join(x))
    df["resp_raw"] = df["resp_raw"].apply(lambda x: b"".join(x))
    return df


def get_retro_details(db, test_name, limit=1000):
    """Return db details for a retro test"""
    c = db.execute_sql(
        "select * from (Select * from retrotest where name = %s and violation = 'Breaks specification' LIMIT %s) as dt JOIN url ON dt.url_id = url.id",
        (
            test_name,
            limit,
        ),
    )
    columns = [col.name for col in c.description]
    df = pd.DataFrame(c.fetchall(), columns=columns)
    return df


def common_errors(db):
    """Calculate common errors."""
    c = db.execute_sql(
        "select count(id) as c, error, msg, req_type from reqresp GROUP by error, msg, req_type order by c desc;"
    )
    errors = pd.DataFrame(c.fetchall(), columns=["count", "error", "msg", "req_type"])
    error_counts = {}
    for error in errors["error"]:
        c = db.execute_sql(
            "select count(id) as c, url_id from reqresp where error = %s GROUP by url_id order by c desc;",
            (error,),
        )
        error_counts[error] = pd.DataFrame(c.fetchall(), columns=["count", "url_id"])
    return error_counts


def plot_errors(error_counts):
    """Plot common errors."""
    for error, df in error_counts.items():
        if len(df) > 10:
            stats = df["count"].agg(["count", "min", "max", "mean", "std"])
            if stats["count"] > 10:
                print(f"Error: {error}; URL distribution:")
                print(stats)
            if stats["std"] > 0:
                display(df["count"].plot(kind="box"))
                plt.show()


def count_percentages(x):
    """Count how many percent of responses violate a rule."""
    breakage = int(x.loc[x["violation"] == "Breaks specification"]["count"].sum())
    valid = int(x.loc[x["violation"] == "Follows specification"]["count"].sum())
    try:
        res = breakage / (breakage + valid)
    except ZeroDivisionError:
        res = 0
    return res
