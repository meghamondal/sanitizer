import re
from html import unescape
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, ConfigDict, StrictStr


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
# REQUEST SCHEMA
# ============================================================

class SanitizeRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    channel: StrictStr
    output: StrictStr


# ============================================================
# INVALID SCHEMA HANDLERS
# ============================================================

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }
    )


# ============================================================
# RESULT HELPERS
# ============================================================

def allow():
    return {
        "safe": True,
        "reason": "SAFE"
    }


def block(reason):
    return {
        "safe": False,
        "reason": reason
    }


# ============================================================
# ONE-TIME DECODING
# ============================================================

UNICODE_PATTERN = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)

ENTITY_PATTERN = re.compile(
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


def decode_entity(match):

    decimal = match.group(1)
    hexadecimal = match.group(2)
    named = match.group(3)

    if decimal is not None:
        try:
            return chr(int(decimal))
        except (ValueError, OverflowError):
            return match.group(0)

    if hexadecimal is not None:
        try:
            return chr(int(hexadecimal, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    named_entities = {
        "lt": "<",
        "gt": ">",
        "quot": '"',
        "apos": "'",
        "amp": "&",
    }

    return named_entities.get(
        named.lower(),
        match.group(0)
    )


def decode_once(value):

    # 1. Percent escapes
    try:
        value = unquote(value)
    except Exception:
        pass

    # 2. HTML entities
    value = ENTITY_PATTERN.sub(
        decode_entity,
        value
    )

    # 3. \uXXXX escapes
    value = UNICODE_PATTERN.sub(
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

        results = []
        for match in pattern.finditer(output):
            value = match.group(1)
            if value is None:
                value = match.group(2)
            results.append(value)
        return results

    if channel == "markdown":
        results = []
        start = 0

        while True:
            marker = output.find("](", start)
            if marker == -1:
                break

            pos = marker + 2
            if pos >= len(output):
                break

            target = ""
            if output[pos] == "<":
                end = output.find(">", pos + 1)
                if end == -1:
                    break
                target = output[pos + 1:end]
            else:
                depth = 0
                end = None
                i = pos

                while i < len(output):
                    char = output[i]
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        if depth == 0:
                            end = i
                            break
                        depth -= 1
                    i += 1

                if end is None:
                    break

                raw_target = output[pos:end].strip()
                if raw_target:
                    target = raw_target.split()[0]

            if target:
                results.append(target)

            start = pos + 1

        return results

    return []


# ============================================================
# DANGEROUS SCHEME
# ============================================================

DANGEROUS_SCHEME_PATTERN = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE
)


def has_dangerous_scheme(channel, output):
    # Only applies to html, markdown, url channels
    if channel not in {"html", "markdown", "url"}:
        return False

    # 1. Direct dangerous scheme anywhere in output text
    if DANGEROUS_SCHEME_PATTERN.search(output):
        return True

    # 2. Check extracted URLs for non http/https schemes
    for value in extract_urls(channel, output):
        value = value.strip()

        if value.startswith("//"):
            value = "https:" + value

        parsed = urlparse(value)

        # If an explicit scheme is present, it MUST be http or https
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return True

    return False


# ============================================================
# EXTERNAL EXFILTRATION
# ============================================================

def has_external_exfil(channel, output):
    if channel not in {"html", "markdown", "url"}:
        return False

    for value in extract_urls(channel, output):
        value = value.strip()

        # Relative references like /local/page are fine
        if value.startswith("/") and not value.startswith("//"):
            continue

        # Protocol-relative references
        if value.startswith("//"):
            parsed = urlparse("https:" + value)
        else:
            parsed = urlparse(value)

        # No scheme or netloc means relative path
        if not parsed.scheme and not parsed.netloc:
            continue

        # Check scheme (non-http/https is handled by dangerous scheme)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            continue

        # Hostname extraction & strict allowlist match
        hostname = parsed.hostname
        if hostname is None:
            return True

        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ============================================================
# CHANNEL RULES
# ============================================================

def html_reason(output):

    # 1. SCRIPT_TAG
    if re.search(
        r"<\s*(?:script|iframe|object|embed)[\s/>]",
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


def markdown_reason(output):
    if has_dangerous_scheme("markdown", output):
        return "DANGEROUS_SCHEME"

    if has_external_exfil("markdown", output):
        return "EXTERNAL_EXFIL"

    return None


def url_reason(output):
    if has_dangerous_scheme("url", output):
        return "DANGEROUS_SCHEME"

    if has_external_exfil("url", output):
        return "EXTERNAL_EXFIL"

    return None


def sql_reason(output):
    if "'" in output or '"' in output or ";" in output or "--" in output or "/*" in output:
        return "SQL_METACHAR"

    if re.search(r"\bunion\b", output, re.IGNORECASE):
        return "SQL_METACHAR"

    if re.search(r"\bor\s+1\s*=\s*1\b", output, re.IGNORECASE):
        return "SQL_METACHAR"

    return None


def shell_reason(output):
    if any(char in output for char in ";&|`<>" or "$(" in output or "${" in output):
        return "SHELL_METACHAR"

    if "$(" in output or "${" in output:
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
async def sanitize_output(
    request: SanitizeRequest
):
    channel = request.channel
    output = request.output

    # RULE 1: Length and Channel Check
    if channel not in ALLOWED_CHANNELS or len(output) > 20000:
        return block("INVALID_SCHEMA")

    # RULE 2: ENCODED_PAYLOAD Check
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = channel_reason(channel, decoded)
        if decoded_reason is not None:
            return block("ENCODED_PAYLOAD")

    # RULE 3: ORIGINAL OUTPUT Check
    reason = channel_reason(channel, output)
    if reason is not None:
        return block(reason)

    return allow()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health():
    return {"status": "ok"}