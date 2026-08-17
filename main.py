import json
import re
from html import unescape
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-99g27ts.example",
    "app-ha3o3z4.example",
}

ALLOWED_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


# ============================================================
# RESULT HELPERS
# ============================================================

def safe_result():
    return {
        "safe": True,
        "reason": "SAFE"
    }


def unsafe_result(reason):
    return {
        "safe": False,
        "reason": reason
    }


# ============================================================
# ONE-TIME DECODING
# ============================================================

UNICODE_ESCAPE = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)

HTML_ENTITY = re.compile(
    r"""
    &
    (?:
        \#([0-9]+)
        |
        \#[xX]([0-9a-fA-F]+)
        |
        (lt|gt|quot|apos|amp)
    )
    ;
    """,
    re.VERBOSE | re.IGNORECASE
)


def decode_html_entity(match):

    decimal = match.group(1)
    hexadecimal = match.group(2)
    named = match.group(3)

    if decimal is not None:
        try:
            return chr(int(decimal, 10))
        except (ValueError, OverflowError):
            return match.group(0)

    if hexadecimal is not None:
        try:
            return chr(int(hexadecimal, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    names = {
        "lt": "<",
        "gt": ">",
        "quot": '"',
        "apos": "'",
        "amp": "&",
    }

    return names.get(named.lower(), match.group(0))


def decode_once(value):

    # 1. Percent escapes
    value = unquote(value)

    # 2. HTML entities
    value = HTML_ENTITY.sub(
        decode_html_entity,
        value
    )

    # 3. Unicode escapes
    value = UNICODE_ESCAPE.sub(
        lambda m: chr(int(m.group(1), 16)),
        value
    )

    return value


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(channel, output):

    if channel == "url":
        return [output.strip()]

    if channel == "html":

        # Only quoted src/href attributes.
        pattern = re.compile(
            r"""
            \b
            (?:src|href)
            \s*=\s*
            (?:
                "([^"]*)"
                |
                '([^']*)'
            )
            """,
            re.IGNORECASE | re.VERBOSE
        )

        urls = []

        for match in pattern.finditer(output):
            value = (
                match.group(1)
                if match.group(1) is not None
                else match.group(2)
            )
            urls.append(value)

        return urls

    if channel == "markdown":

        # Extract target inside ](...)
        pattern = re.compile(
            r"\]\((.*?)\)",
            re.DOTALL
        )

        urls = []

        for match in pattern.finditer(output):

            target = match.group(1).strip()

            if not target:
                continue

            # <URL>
            if target.startswith("<"):
                end = target.find(">")

                if end != -1:
                    target = target[1:end]

            else:
                # URL is first whitespace-delimited token.
                target = target.split()[0]

            urls.append(target)

        return urls

    return []


# ============================================================
# URL HELPERS
# ============================================================

DANGEROUS_SCHEME = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE
)


def normalize_protocol_relative(url):

    url = url.strip()

    if url.startswith("//"):
        return "https:" + url

    return url


def has_dangerous_scheme(channel, output):

    # The specification says the TEXT contains these schemes,
    # so inspect the original text as a whole.
    if DANGEROUS_SCHEME.search(output):
        return True

    # Also inspect extracted URLs for non-http/https schemes.
    for value in extract_urls(channel, output):

        value = normalize_protocol_relative(value)

        parsed = urlparse(value)

        if parsed.scheme:

            if parsed.scheme.lower() not in {
                "http",
                "https"
            }:
                return True

    return False


def has_external_exfil(channel, output):

    for value in extract_urls(channel, output):

        value = value.strip()

        # Protocol-relative references are absolute.
        if value.startswith("//"):
            parsed = urlparse("https:" + value)

        else:
            parsed = urlparse(value)

        # Relative URL.
        if not parsed.scheme:
            continue

        # Dangerous schemes are handled first.
        if parsed.scheme.lower() not in {
            "http",
            "https"
        }:
            continue

        # IMPORTANT:
        # hostname excludes username, password, port,
        # path and query.
        hostname = parsed.hostname

        if hostname is None:
            return True

        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ============================================================
# HTML
# ============================================================

def html_reason(output):

    # 1. SCRIPT_TAG
    if re.search(
        r"<\s*(?:script|iframe|object|embed)\b",
        output,
        re.IGNORECASE
    ):
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if re.search(
        r"\bon[a-zA-Z0-9_-]+\s*=",
        output,
        re.IGNORECASE
    ):
        return "EVENT_HANDLER"

    # 3. DANGEROUS_SCHEME
    if has_dangerous_scheme("html", output):
        return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL
    if has_external_exfil("html", output):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# MARKDOWN
# ============================================================

def markdown_reason(output):

    # 1. DANGEROUS_SCHEME
    if has_dangerous_scheme("markdown", output):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if has_external_exfil("markdown", output):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# URL
# ============================================================

def url_reason(output):

    # 1. DANGEROUS_SCHEME
    if has_dangerous_scheme("url", output):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if has_external_exfil("url", output):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# SQL
# ============================================================

def sql_reason(output):

    if "'" in output:
        return "SQL_METACHAR"

    if '"' in output:
        return "SQL_METACHAR"

    if ";" in output:
        return "SQL_METACHAR"

    if "--" in output:
        return "SQL_METACHAR"

    if "/*" in output:
        return "SQL_METACHAR"

    if re.search(r"\bunion\b", output, re.IGNORECASE):
        return "SQL_METACHAR"

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        output,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"

    return None


# ============================================================
# SHELL
# ============================================================

def shell_reason(output):

    if any(c in output for c in "; &|`<>"):
        return "SHELL_METACHAR"

    if "$(" in output:
        return "SHELL_METACHAR"

    if "${" in output:
        return "SHELL_METACHAR"

    return None


# ============================================================
# CHANNEL DISPATCH
# ============================================================

def channel_reason(channel, output):

    if channel == "html":
        return html_reason(output)

    if channel == "markdown":
        return markdown_reason(output)

    if channel == "url":
        return url_reason(output)

    if channel == "sql":
        return sql_reason(output)

    if channel == "shell":
        return shell_reason(output)

    return "INVALID_SCHEMA"


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # --------------------------------------------------------
    # RULE 1: INVALID_SCHEMA
    # --------------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return unsafe_result("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return unsafe_result("INVALID_SCHEMA")

    if "channel" not in body:
        return unsafe_result("INVALID_SCHEMA")

    if "output" not in body:
        return unsafe_result("INVALID_SCHEMA")

    channel = body["channel"]
    output = body["output"]

    if channel not in ALLOWED_CHANNELS:
        return unsafe_result("INVALID_SCHEMA")

    if not isinstance(output, str):
        return unsafe_result("INVALID_SCHEMA")

    if len(output) > 20000:
        return unsafe_result("INVALID_SCHEMA")


    # --------------------------------------------------------
    # RULE 2: ENCODED_PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = channel_reason(
            channel,
            decoded
        )

        if decoded_reason is not None:
            return unsafe_result("ENCODED_PAYLOAD")


    # --------------------------------------------------------
    # RULE 3: ORIGINAL OUTPUT
    # --------------------------------------------------------

    reason = channel_reason(
        channel,
        output
    )

    if reason is not None:
        return unsafe_result(reason)


    return safe_result()


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def health():
    return {"status": "ok"}