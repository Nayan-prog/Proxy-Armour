import pytest

from app.detectors.ast_detector import AstDetector, is_sensitive_name

detector = AstDetector()


def values(text):
    return [text[f["start"]:f["end"]] for f in detector.detect(text)]


def test_findings_have_the_common_shape_and_exclude_quotes():
    text = 'password = "hunter22"'
    f, = detector.detect(text)
    assert f == {"type": "HARDCODED_SECRET", "start": 12, "end": 20,
                 "severity": "high", "detector": "ast"}
    assert text[f["start"] - 1] == '"' and text[f["end"]] == '"'


@pytest.mark.parametrize("code,secret", [
    ('db_password = "hunter22"', "hunter22"),                           # Assign
    ('a = b_token = "tok_9999"', "tok_9999"),                           # chained Assign
    ('api_key: str = "abc123xyz"', "abc123xyz"),                        # AnnAssign
    ('self.apiKey = "k-12345"', "k-12345"),                             # Attribute target
    ('cfg["db_secret"] = "s3cr3tvalue"', "s3cr3tvalue"),                # Subscript target
    ('conn = connect(host="db", password="s3cr3tpw")', "s3cr3tpw"),     # keyword
    ('h = {"Authorization": "Bearer abc123", "Accept": "json"}', "Bearer abc123"),  # Dict
    ('{"user": "bob", "passwd": "jsonpass1"}', "jsonpass1"),           # pasted JSON
    ("PRIVATE_KEY = '''line1\nline2'''", "line1\nline2"),               # multi-line literal
    ("TOKEN = r'raw\\token'", "raw\\token"),                            # prefixed literal
    ('DATABASE_CONN_STR = "Server=x;Pwd=y"', "Server=x;Pwd=y"),
    ('client_credentials = "cid:csecret"', "cid:csecret"),
])
def test_hardcoded_secrets_are_found(code, secret):
    assert values(code) == [secret]


def test_offsets_are_characters_not_utf8_bytes():
    # "é" is 2 bytes in UTF-8; ast col_offset counts bytes
    text = 'greeting = "héllo wörld"; password = "hunter22"'
    assert values(text) == ["hunter22"]


def test_offsets_are_absolute_inside_prose_and_fences():
    text = ("Hi, my script fails:\n\n```python\nimport os\n"
            "SECRET_KEY = \"django-insecure-abc\"\n```\n\nAlso:\n    password = \"indented1\"\nthanks")
    assert values(text) == ["django-insecure-abc", "indented1"]


def test_crlf_line_endings():
    assert values('x = 1\r\napi_key = "abc123xyz"\r\n') == ["abc123xyz"]


@pytest.mark.parametrize("code", [
    'author = "Jane Doe"',                     # "auth" inside another word
    'tokenizer = "bert-base-uncased"',         # "token" inside another word
    'password = ""',                           # empty
    'password = "abc"',                        # too short to be real
    'password = os.environ["DB_PASSWORD"]',    # not a literal
    'password = get_password()',
    'username = "admin"',                      # not a sensitive name
    'print("my password is hunter22")',        # literal not assigned to a name
    'token_count = 512',                       # not a string
    'password = f"{prefix}abc123"',            # f-string, not a constant
    'password = b"bytes-value"',               # bytes, not str
])
def test_true_negatives(code):
    assert detector.detect(code) == []


@pytest.mark.parametrize("text", [
    "The password is stored in the vault, not in the code.",
    "def broken(:\n    return ))",
    "null byte \x00 password = 'hunter22'",
    "[" * 5000,
    "(" * 200_000,
    "",
], ids=["prose", "syntax-error", "null-byte", "deep-brackets", "huge-parens", "empty"])
def test_non_python_text_never_crashes(text):
    detector.detect(text)                       # must not raise


@pytest.mark.parametrize("name,expected", [
    ("password", True), ("DB_PASSWORD", True), ("passwd", True), ("apiKey", True),
    ("APIKEY", True), ("x-api-key", True), ("Authorization", True), ("auth", True),
    ("private_key", True), ("privateKey", True), ("conn_str", True), ("connection_str", True),
    ("connectionString", True), ("secrets", True), ("credential", True),
    ("author", False), ("tokenizer", False), ("authority", False), ("username", False),
    ("passage", False), ("secretary", False),
])
def test_sensitive_name_matching(name, expected):
    assert is_sensitive_name(name) is expected
