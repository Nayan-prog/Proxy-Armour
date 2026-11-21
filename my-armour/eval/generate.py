"""Build the labelled synthetic evaluation corpus (seeded, reproducible).

    python -m eval.generate            # -> eval/data/corpus.jsonl (git-ignored)

Every sample: {"id", "split" (dev|test), "category", "text", "spans": [{start, end, type}]}.
Spans mark exactly the sensitive VALUE (inside quotes, without the quotes).
Samples with no spans are hard negatives.

The corpus contains realistic-looking (fake) keys, so it is regenerated rather
than committed - same seed, same corpus. Nothing here is tuned on the test split:
the split is decided by a seeded shuffle before any detector runs.
"""
import base64
import json
import random
import string
from pathlib import Path

from app.detectors.checksums import luhn_valid, verhoeff_check_digit, verhoeff_valid

SEED = 20261119
OUT = Path(__file__).resolve().parent / "data" / "corpus.jsonl"
TEST_FRACTION = 0.30

ALNUM = string.ascii_letters + string.digits
WORDS = ("orbit", "falcon", "maple", "copper", "delta", "nimbus", "quartz", "harbor", "ember", "lotus",
         "summit", "cobalt", "violet", "atlas", "river", "pixel", "tango", "willow", "zephyr", "granite")
FIRST = ("rahul", "priya", "amit", "sneha", "arjun", "kavya", "vikram", "ananya", "rohan", "isha", "maria", "john")
DOMAINS = ("acme.com", "example.org", "corp.in", "mail.example.net", "startup.io", "uni.ac.in")
HOSTS = ("db.internal", "10.0.3.17", "pg-prod.acme.local", "mysql.svc.cluster.local", "cluster0.ab12c.mongodb.net")


class Builder:
    """Concatenate text pieces; pieces given a type become ground-truth spans."""

    def __init__(self):
        self.parts: list[str] = []
        self.spans: list[dict] = []
        self.length = 0

    def add(self, text: str, type_: str | None = None) -> "Builder":
        if type_:
            self.spans.append({"start": self.length, "end": self.length + len(text), "type": type_})
        self.parts.append(text)
        self.length += len(text)
        return self

    def build(self) -> tuple[str, list[dict]]:
        return "".join(self.parts), self.spans


# ------------------------------------------------------------------ value generators

class Values:
    def __init__(self, rng: random.Random):
        self.r = rng

    def rand(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def password(self) -> str:
        """Human-chosen passwords: low entropy, no fixed format (only context reveals them)."""
        r = self.r
        return r.choice([
            lambda: f"{r.choice(WORDS).capitalize()}{r.randint(1990, 2026)}!",
            lambda: f"{r.choice(WORDS)}-{r.choice(WORDS)}-{r.randint(10, 99)}",
            lambda: f"{r.choice(FIRST)}@{r.randint(100, 999)}",
            lambda: f"P@ssw0rd{r.randint(1, 999)}",
            lambda: f"{r.choice(WORDS)}{r.randint(1000, 9999)}",
            lambda: self.rand(ALNUM, r.randint(10, 16)),
        ])()

    def generic_key(self) -> str:
        """Vendor API key with no known prefix (random, high entropy)."""
        r = self.r
        if r.random() < 0.3:
            return self.rand("0123456789abcdef", r.choice([32, 40]))
        while True:      # mixed case + digits, like most vendor keys
            key = self.rand(ALNUM, r.choice([24, 32, 40]))
            if any(c.isdigit() for c in key) and any(c.isupper() for c in key) and any(c.islower() for c in key):
                return key

    def aws(self):
        return "AKIA" + self.rand(string.ascii_uppercase + "234567", 16)

    def github(self):
        return "ghp_" + self.rand(ALNUM, 36)

    def stripe(self):
        return "sk_" + self.r.choice(["live", "test"]) + "_" + self.rand(ALNUM, 24)

    def slack(self):
        return f"xox{self.r.choice('bp')}-{self.rand(string.digits, 11)}-{self.rand(string.digits, 12)}-{self.rand(ALNUM, 24)}"

    def google(self):
        return "AIza" + self.rand(ALNUM + "-_", 35)

    def openai(self):
        return "sk-proj-" + self.rand(ALNUM + "-_", 48)

    def anthropic(self):
        return "sk-ant-api03-" + self.rand(ALNUM + "-_", 40)

    def jwt(self):
        b64 = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        header = b64({"alg": self.r.choice(["HS256", "RS256"]), "typ": "JWT"})
        payload = b64({"sub": str(self.r.randint(1000, 99999)), "role": self.r.choice(["admin", "user"])})
        return f"{header}.{payload}.{self.rand(ALNUM + '-_', 43)}"

    def private_key(self):
        kind = self.r.choice(["RSA ", "EC ", "OPENSSH ", ""])
        body = "\n".join(self.rand(ALNUM + "+/", 64) for _ in range(self.r.randint(3, 6)))
        return f"-----BEGIN {kind}PRIVATE KEY-----\n{body}\n-----END {kind}PRIVATE KEY-----"

    def db_url(self):
        scheme = self.r.choice(["postgresql", "postgres", "mysql", "mongodb+srv", "postgresql+psycopg"])
        return (f"{scheme}://{self.r.choice(['admin', 'app', 'svc_user', 'root'])}:{self.password()}"
                f"@{self.r.choice(HOSTS)}:{self.r.choice([5432, 3306, 27017])}/{self.r.choice(['payments', 'app', 'users'])}")

    def email(self):
        return f"{self.r.choice(FIRST)}{self.r.choice(['', '.', '_'])}{self.r.choice(FIRST)}{self.r.randint(1, 99)}@{self.r.choice(DOMAINS)}"

    def phone(self):
        n = str(self.r.randint(6, 9)) + self.rand(string.digits, 9)
        return self.r.choice([n, f"+91 {n[:5]} {n[5:]}", f"+91-{n}", f"{n[:5]}-{n[5:]}", f"{n[:3]} {n[3:6]} {n[6:]}"])

    def aadhaar(self):
        base = str(self.r.randint(2, 9)) + self.rand(string.digits, 10)
        n = base + verhoeff_check_digit(base)
        return self.r.choice([n, f"{n[:4]} {n[4:8]} {n[8:]}", f"{n[:4]}-{n[4:8]}-{n[8:]}"])

    def pan(self):
        return self.rand(string.ascii_uppercase, 3) + self.r.choice("PCHFATBLJG") + \
            self.rand(string.ascii_uppercase, 1) + self.rand(string.digits, 4) + self.rand(string.ascii_uppercase, 1)

    def card(self):
        prefix, length = self.r.choice([("4", 16), ("51", 16), ("55", 16), ("37", 15), ("6011", 16)])
        while True:
            n = prefix + self.rand(string.digits, length - len(prefix))
            if luhn_valid(n):
                break
        if length == 16 and self.r.random() < 0.5:
            sep = self.r.choice([" ", "-"])
            return sep.join(n[i:i + 4] for i in range(0, 16, 4))
        return n

    # -- look-alikes that must NOT be flagged ---------------------------------
    def aadhaar_lookalike(self):
        while True:
            n = str(self.r.randint(2, 9)) + self.rand(string.digits, 11)
            if not verhoeff_valid(n):
                return n

    def card_lookalike(self):
        while True:
            n = "4" + self.rand(string.digits, 15)
            if not luhn_valid(n):
                return n

    def uuid(self):
        h = self.rand("0123456789abcdef", 32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}"

    def sha(self, n=40):
        return self.rand("0123456789abcdef", n)


# Known-format secrets: (type, generator)
FORMATS = ["AWS_KEY", "GITHUB_TOKEN", "STRIPE_KEY", "SLACK_TOKEN", "GOOGLE_API_KEY", "OPENAI_KEY",
           "ANTHROPIC_KEY", "JWT", "DB_CONNECTION_STRING"]


def format_value(v: Values, type_: str) -> str:
    return {"AWS_KEY": v.aws, "GITHUB_TOKEN": v.github, "STRIPE_KEY": v.stripe, "SLACK_TOKEN": v.slack,
            "GOOGLE_API_KEY": v.google, "OPENAI_KEY": v.openai, "ANTHROPIC_KEY": v.anthropic,
            "JWT": v.jwt, "DB_CONNECTION_STRING": v.db_url}[type_]()


SECRET_NAMES = ("password", "db_password", "DB_PASSWORD", "admin_pass" + "word", "api_key", "API_KEY", "apiKey",
                "secret", "SECRET_KEY", "client_secret", "auth_token", "access_token", "token", "private_key",
                "credential", "conn_str", "smtp_password")


def secret_and_type(v: Values) -> tuple[str, str]:
    """A secret for a code context: a password (60%), a known format (25%) or a vendor key (15%)."""
    x = v.r.random()
    if x < 0.6:
        return v.password(), "HARDCODED_SECRET"
    if x < 0.85:
        t = v.r.choice(FORMATS)
        return format_value(v, t), t
    return v.generic_key(), "HARDCODED_SECRET"


def filler_code(v: Values) -> str:
    r = v.r
    return r.choice([
        f"timeout = {r.randint(5, 120)}\n",
        f"retries = {r.randint(1, 5)}\n",
        f"region = \"{r.choice(['ap-south-1', 'us-east-1', 'eu-west-2'])}\"\n",
        f"logger = logging.getLogger(\"{r.choice(WORDS)}\")\n",
        f"BASE_URL = \"https://api.{r.choice(WORDS)}.com/v{r.randint(1, 3)}\"\n",
        f"username = \"{r.choice(FIRST)}\"\n",
        "DEBUG = False\n",
    ])


# ------------------------------------------------------------------ sample makers

def py_assign(v):
    b = Builder().add("import logging\n\n")
    for _ in range(v.r.randint(0, 2)):
        b.add(filler_code(v))
    secret, t = secret_and_type(v)
    name, quote = v.r.choice(SECRET_NAMES), v.r.choice(['"', "'"])
    b.add(f"{name}{v.r.choice([' = ', ': str = '])}{quote}").add(secret, t).add(f"{quote}\n")
    b.add(filler_code(v))
    return b


def py_dict(v):
    secret, t = secret_and_type(v)
    key = v.r.choice(["password", "api_key", "token", "secret", "Authorization", "client_secret", "passwd"])
    b = Builder().add("CONFIG = {\n").add(f"    \"host\": \"{v.r.choice(HOSTS)}\",\n")
    b.add(f"    \"{key}\": \"").add(secret, t).add("\",\n")
    b.add(f"    \"timeout\": {v.r.randint(5, 60)},\n}}\n")
    return b


def py_kwargs(v):
    secret, t = secret_and_type(v)
    call = v.r.choice(["psycopg.connect", "smtplib.SMTP_SSL(host).login", "Client", "requests.post"])
    kw = v.r.choice(["password", "api_key", "token", "secret", "auth_token"])
    b = Builder().add(f"conn = {call}(\n    host=\"{v.r.choice(HOSTS)}\",\n    user=\"{v.r.choice(FIRST)}\",\n")
    b.add(f"    {kw}=\"").add(secret, t).add("\",\n)\n")
    return b


def py_comment(v):
    # secret only mentioned in a comment: no assignment for the AST detector to see
    secret, t = secret_and_type(v)
    b = Builder().add("def connect():\n")
    b.add(f"    # {v.r.choice(['temp', 'TODO remove:', 'old', 'staging'])} {v.r.choice(['password', 'key', 'token'])} is ")
    b.add(secret, t).add("\n    return open_connection(os.environ[\"DB_PASSWORD\"])\n")
    return b


def py_fstring(v):
    # secret embedded in an f-string: JoinedStr, not a plain constant
    secret, t = secret_and_type(v)
    b = Builder().add("user_id = get_user()\n")
    form = v.r.choice(["header", "url"])
    if form == "header":
        b.add("headers = {\"Authorization\": f\"Bearer ").add(secret, t).add("-{user_id}\"}\n")
    else:
        b.add(f"url = f\"https://api.{v.r.choice(WORDS)}.com/data?user={{user_id}}&key=").add(secret, t).add("\"\n")
    return b


def json_config(v):
    secret, t = secret_and_type(v)
    key = v.r.choice(["password", "apiKey", "token", "secret", "client_secret", "dbPassword"])
    b = Builder().add("{\n  \"service\": \"").add(v.r.choice(WORDS)).add("\",\n")
    b.add(f"  \"port\": {v.r.randint(3000, 9000)},\n  \"{key}\": \"").add(secret, t).add("\",\n")
    if v.r.random() < 0.4:
        b.add("  \"owner\": \"").add(v.email(), "EMAIL").add("\",\n")
    b.add("  \"debug\": false\n}\n")
    return b


def env_text(v):
    b = Builder().add(f"# .env for {v.r.choice(WORDS)}\n")
    b.add(f"APP_NAME={v.r.choice(WORDS)}\nPORT={v.r.randint(3000, 9000)}\n")
    for _ in range(v.r.randint(1, 3)):
        x = v.r.random()
        if x < 0.35:
            b.add(f"{v.r.choice(['DB_PASSWORD', 'SMTP_PASSWORD', 'ADMIN_PASS' + 'WORD'])}=").add(v.password(), "HARDCODED_SECRET").add("\n")
        elif x < 0.7:
            t = v.r.choice(FORMATS)
            b.add(f"{t}=").add(format_value(v, t), t).add("\n")
        else:
            b.add(f"{v.r.choice(['VENDOR', 'MAPS', 'PAYMENTS', 'SMS'])}_API_KEY=").add(v.generic_key(), "HARDCODED_SECRET").add("\n")
    b.add("LOG_LEVEL=info\n")
    return b


def prose_pii(v):
    r = v.r
    b = Builder().add(r.choice(["Hi team, ", "Please update the customer record: ", "Escalation - ", "Note: "]))
    items = r.sample(["EMAIL", "PHONE_IN", "AADHAAR", "PAN", "CREDIT_CARD"], r.randint(1, 3))
    for i, t in enumerate(items):
        label = {"EMAIL": "email", "PHONE_IN": "phone", "AADHAAR": "Aadhaar", "PAN": "PAN", "CREDIT_CARD": "card"}[t]
        value = {"EMAIL": v.email, "PHONE_IN": v.phone, "AADHAAR": v.aadhaar, "PAN": v.pan, "CREDIT_CARD": v.card}[t]()
        b.add(f"{'their' if i else 'the customer'} {label} is ").add(value, t)
        b.add("; " if i < len(items) - 1 else ". ")
    b.add(r.choice(["Thanks!", "Can you summarise the ticket?", "Draft a polite reply.", ""]))
    return b


def prose_keys(v):
    r = v.r
    b = Builder().add(r.choice(["Why does this fail? I'm using ", "Rotate this key please: ", "My deploy logs show "]))
    # every known format, private keys and prefix-less vendor keys equally likely
    t = r.choice(FORMATS + ["PRIVATE_KEY", "VENDOR_KEY"])
    if t == "PRIVATE_KEY":
        b.add("this key:\n").add(v.private_key(), "PRIVATE_KEY").add("\n")
    elif t == "VENDOR_KEY":
        b.add("the vendor key ").add(v.generic_key(), "HARDCODED_SECRET").add(" with their SDK.")
    else:
        b.add(f"{r.choice(['', 'the token ', 'key '])}").add(format_value(v, t), t).add(r.choice([" in production.", " - is that right?", ""]))
    return b


def hard_negative(v):
    r = v.r
    kind = r.choice(["uuid", "git", "sha256", "ids", "numbers", "aadhaar_like", "card_like", "phone_like",
                     "code_env", "code_empty", "identifiers", "prose"])
    b = Builder()
    if kind == "uuid":
        b.add(f"Request {v.uuid()} failed for tenant {v.uuid()} at step 3.")
    elif kind == "git":
        b.add(f"Regression introduced in commit {v.sha()} - see git log; reverted by {r.choice(['commit', 'sha'])} {v.sha()}.")
    elif kind == "sha256":
        b.add(f"Download verified: sha256: {v.sha(64)} (checksum OK)")
    elif kind == "ids":
        b.add(f"order_id={r.randint(10**8, 10**9)} invoice INV-{r.randint(1000, 9999)} ref {v.rand(string.ascii_uppercase, 3)}-{r.randint(100, 999)}")
    elif kind == "numbers":
        b.add(f"Revenue grew {r.randint(1000000, 9999999)} INR in Q{r.randint(1, 4)}; {r.randint(10, 99)}.{r.randint(0, 9)}% margin, {r.randint(1000, 9999)} units.")
    elif kind == "aadhaar_like":
        n = v.aadhaar_lookalike()
        b.add(f"Tracking number {n[:4]} {n[4:8]} {n[8:]} was dispatched.")
    elif kind == "card_like":
        b.add(f"Shipment reference {v.card_lookalike()} received.")
    elif kind == "phone_like":
        b.add(f"Call extension {r.randint(1, 5)}{v.rand(string.digits, 9)} for support.")
    elif kind == "code_env":
        b.add("password = os.environ[\"DB_PASSWORD\"]\ntoken = get_token()\napi_key = settings.API_KEY\n")
    elif kind == "code_empty":
        b.add("password = \"\"\nauthor = \"Jane Doe\"\ntokenizer = \"bert-base-uncased\"\nsecret_santa = True\n")
    elif kind == "identifiers":
        b.add(f"self.max_retries_v2 = {r.randint(1, 9)}\nresult = compute_checksum_for_partition_{r.randint(10, 99)}(batch)\n")
    else:
        b.add(r.choice(["The password policy requires 12 characters and rotation every 90 days.",
                        "Our API keys are stored in the vault, never in code.",
                        "What is the capital of France?",
                        "Summarise the meeting notes from Tuesday's standup."]))
    return b


MAKERS = [  # (category, maker, count)
    ("py_assign", py_assign, 80), ("py_dict", py_dict, 50), ("py_kwargs", py_kwargs, 50),
    ("py_comment", py_comment, 30), ("py_fstring", py_fstring, 30), ("json_config", json_config, 60),
    ("env_text", env_text, 60), ("prose_pii", prose_pii, 100), ("prose_keys", prose_keys, 66),
    ("hard_negative", hard_negative, 84),
]


def generate(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    v = Values(rng)
    samples = []
    for category, maker, count in MAKERS:
        for i in range(count):
            text, spans = maker(v).build()
            for s in spans:                                     # self-check: spans point at the value
                assert text[s["start"]:s["end"]] and text[s["start"]] not in "\"' "
            samples.append({"id": f"{category}-{i:03d}", "category": category, "text": text, "spans": spans})
    # split: seeded shuffle within each category (stratified), decided before any detector runs
    by_cat: dict[str, list[dict]] = {}
    for s in samples:
        by_cat.setdefault(s["category"], []).append(s)
    for items in by_cat.values():
        rng.shuffle(items)
        n_test = round(len(items) * TEST_FRACTION)
        for j, s in enumerate(items):
            s["split"] = "test" if j < n_test else "dev"
    return samples


def load(split: str | None = None) -> list[dict]:
    if not OUT.exists():
        write()
    rows = [json.loads(line) for line in OUT.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if split is None or r["split"] == split]


def write() -> list[dict]:
    samples = generate()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(json.dumps(s) for s in samples) + "\n", encoding="utf-8")
    return samples


if __name__ == "__main__":
    s = write()
    test = [x for x in s if x["split"] == "test"]
    spans = sum(len(x["spans"]) for x in s)
    print(f"{len(s)} samples ({len(s) - len(test)} dev / {len(test)} test), {spans} labelled spans, "
          f"{sum(1 for x in s if not x['spans'])} hard negatives -> {OUT}")
