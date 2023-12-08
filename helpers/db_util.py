from dataclasses import dataclass
from datetime import datetime
from strenum import StrEnum


from peewee import (
    TextField,
    DateTimeField,
    ForeignKeyField,
    BlobField,
    IntegerField,
    BooleanField,
    PostgresqlDatabase,
)
from playhouse.signals import pre_save, Model
import psycopg2 


# Connect to PostgreSQL database
db = PostgresqlDatabase(None, autorollback=True)


class BaseModel(Model):
    class Meta:
        database = db


class Site(BaseModel):
    """Metadata for each tested origin/entitity"""

    site_type = TextField()
    description = TextField()
    rank = IntegerField(help_text="Tranco rank")
    t_date = TextField(default="2023-01-30")
    bucket = IntegerField(help_text="CrUX bucket")
    crux_date = TextField(default="202302")
    origin = TextField(unique=True)
    site = TextField()
    reachable = BooleanField(default=True)
    error = TextField(null=True, help_text="Error is not reachable")
    status = TextField(default="free")
    org_scheme = TextField(null=True)


class Url(BaseModel):
    """Metadata for each tested URL"""

    site = ForeignKeyField(Site)
    full_url = TextField()
    scheme = TextField()
    host = TextField()
    port = IntegerField()
    path = TextField()
    description = TextField()
    is_base = BooleanField(default=False)


class Monitoring(BaseModel):
    """Monitoring requests for each tested URL"""

    url = ForeignKeyField(Url)
    susp = TextField(
        default="No",
        help_text="No: nothing suspicious (same status code), NA: failed first request URL not tested, Code: suspicious (different status codes), Error: error after but not before.",
    )
    b_error = TextField(default="")
    a_error = TextField(default="")
    a_rep = IntegerField(default=0)
    b_resp_code = TextField(default="")
    b_resp_version = TextField(default="")
    b_resp_headers = TextField(default="")
    b_resp_body = TextField(default="")
    a_resp_code = TextField(default="")
    a_resp_version = TextField(default="")
    a_resp_headers = TextField(default="")
    a_resp_body = TextField(default="")


class TestBase(BaseModel):
    """Base test results for each test"""

    url = ForeignKeyField(Url, null=True)
    name = TextField(default="", index=True)
    type = TextField(default="", index=True)
    violation = TextField(default="", index=True)
    test_error = TextField(default="", index=True)
    extra = TextField(default="", index=True)
    created_date = DateTimeField(default=datetime.now)

    class Meta:
        indexes = ((("name", "violation"), False),)


class DirectTest(TestBase):
    """Direct test"""

    pass


class ReqResp(BaseModel):
    """Request with raw response data (can be several responses)"""

    created_date = DateTimeField(default=datetime.now)
    url = ForeignKeyField(Url, null=True)
    real_url = TextField()
    probe_id = TextField(
        null=True, index=True
    )  # (<method_id>,<header_id>,<http2_id>) e.g., (1,1,1)

    error = TextField(default="", index=True)
    msg = TextField(default="", index=True)
    direct_test = ForeignKeyField(DirectTest, null=True)

    req_type = TextField(default="", index=True)
    req_method = TextField(default="", index=True)
    req_version = TextField(default="", index=True)
    req_headers = TextField(default="")
    req_body = TextField(default="")
    req_raw = BlobField(default="")

    resp_code = TextField(default="", index=True)
    resp_version = TextField(default="", index=True)
    resp_headers = TextField(default="")
    resp_body = TextField(default="")
    resp_add_data = TextField(default="")
    # For direct tests: Full response data (can contain several responses)
    resp_raw = BlobField(default="")

    class Meta:
        indexes = ((("error", "msg", "req_type"), False),)


@pre_save(sender=ReqResp)
def req_pre_save(model: ReqResp, instance: ReqResp, created: bool):
    if created:
        instance.req_method = repr(instance.req_method)
        instance.req_version = repr(instance.req_version)
        instance.req_headers = repr(instance.req_headers)
        instance.req_body = repr(instance.req_body)

        instance.resp_code = repr(instance.resp_code)
        instance.resp_version = repr(instance.resp_version)
        instance.resp_headers = repr(instance.resp_headers)
        instance.resp_body = repr(instance.resp_body)
        instance.resp_add_data = repr(instance.resp_add_data)


class AddResp(BaseModel):
    """Response data if more than one response received"""

    req = ForeignKeyField(ReqResp)
    error = TextField(default="")
    msg = TextField(default="")
    resp_code = TextField(default="")
    resp_version = TextField(default="")
    resp_headers = TextField(default="")
    resp_body = TextField(default="")
    # Raw data of this response only
    resp_raw = BlobField(default="")


@pre_save(sender=AddResp)
def add_pre_save(model: AddResp, instance: AddResp, created: bool):
    if created:
        instance.resp_code = repr(instance.resp_code)
        instance.resp_version = repr(instance.resp_version)
        instance.resp_headers = repr(instance.resp_headers)
        instance.resp_body = repr(instance.resp_body)


class RedTest(TestBase):
    """Redbot test"""

    req = ForeignKeyField(ReqResp)
    subject = TextField(default="", index=True)
    category = TextField(default="", index=True)
    extra2 = TextField(default="", index=True)


class RetroTest(TestBase):
    """Retroactive test (input all probe req/resp pairs)"""

    pass


class ProbeTest(TestBase):
    """Probe test (runs on the result of a probe)"""

    req = ForeignKeyField(ReqResp)


class Req(BaseModel):
    """Helper to pass request data for direct tests (not saved in DB).
    If request_line is passed directly, req_method, req_version, req_path might be incorrect
    req_raw is always correct
    """

    req_method = TextField(default="")
    req_version = TextField(default="")
    req_headers = TextField(default="")
    req_body = TextField(default="")
    req_raw = BlobField(default="")
    req_path = TextField(default="")


class Level(StrEnum):
    REQUIREMENT = "Requirement"
    RECOMMENDATION = "Recommendation"
    OPTIONAL = "Optional"
    UNCLEAR = "Unclear"
    DEPRECATED = "Deprecated"
    RESERVED = "Reserved"
    ABNF = "ABNF"


class Violation(StrEnum):
    VALID = "Follows specification"
    INVALID = "Breaks specification"
    INAPPLICABLE = "Inapplicable (e.g., only relevant for GET but is a HEAD request)"
    RESERVED = "Reserved"
    DEPRECATED = "Deprecated"
    UNCLEAR = "Unclear (has to be checked)"
    FAILED = "Test failed"


class Activity(StrEnum):
    """How a test can be run."""

    PROXY = "Proxy: Test runs standalone with MITMproxy (given existing probes)"
    DIRECT = "Direct: Test has to be run directly without MITMproxy (e.g., HEAD without body as proxy strips the body)"
    DIRECT_BASE = (
        "Direct: Test has to be run directly; once per 'server' only, not on every URL"
    )
    RETRO = "Retro: Test can run on the results/response database (e.g., compare responses to same URL with HEAD/GET request)"


@dataclass
class TestCase:
    """Helper to present a TestCase as a dataclass."""
    idx: int = None
    function_name: str = None
    title: str = None
    description: str = None
    type: Level = None
    category: str = None
    source: str = None
    activity: Activity = None
    code: str = None
    confidence: int = None
    valid: str = None
    invalid: str = None
    measure_violations: str = None
    probe_feature: str = None
    impact: str = None
    violation_check_implemented: str = None
    probing_implemented: str = None

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)


def setup_db(db_name):
    """Create db_name in Postgres"""
    conn = psycopg2.connect()
    conn.set_session(autocommit=True)
    cursor = conn.cursor()
    cursor.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{db_name}'")
    exists = cursor.fetchone()
    if not exists:
        cursor.execute(f"CREATE DATABASE {db_name}")
    cursor.close()
    conn.close()
