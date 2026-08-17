import re
from html import unescape
from urllib.parse import unquote, urlparse

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
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
# REQUEST MODEL
# ============================================================

class SanitizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: StrictStr
    output: StrictStr


# ============================================================
# INVALID SCHEMA HANDLER
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


# ============================================================
# DECODE ONCE
# ============================================================

def decode_once(value: str) -> str:

    # 1. Percent decoding
    decoded = unquote(value)

    # 2. Required HTML entities only
    entity_pattern = re.compile(
        r"&(?:#\d+|#[xX][0-9a-fA-F]+|lt|gt|quot|apos|amp);",
        re.IGNORECASE
    )

    decoded = entity_pattern.sub(
        lambda m: unescape(m.group(0)),
        decoded
    )

    # 3. Unicode escapes
    unicode_pattern = re.compile(
        r"\\u([0-9a-fA-F]{4})"
    )

    decoded = unicode_pattern.sub(
        lambda m: chr(int(m.group(1), 16)),
        decoded
    )

    return decoded


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(channel: str, output: str):

    urls = []

    if channel == "html":

        pattern = re.compile(
            r'\b(?:src|href)\s*=\s*(?:"([^"]*)"|\'([^\']*)\')',
            re.IGNORECASE
        )

        for match in pattern.finditer(output):

            value = match.group(1)

            if value is None:
                value = match.group(2)

            urls.append(value)


    elif channel == "markdown":

        pattern = re.compile(
            r"\]\(([^)]*)\)"
        )

        for match in pattern.finditer(output):

            target = match.group(1).strip()

            if target.startswith("<"):

                end = target.find(">")

                if end != -1:
                    target = target[1:end]

            else:

                target = target.split()[0]

            urls.append(target)


    elif channel == "url":

        urls.append(output.strip())


    return urls


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(value: str):

    value = value.strip()

    if value.startswith("//"):
        return "https:" + value

    return value


# ============================================================
# DANGEROUS SCHEME
# ============================================================

def dangerous_scheme(channel: str, output: str):

    # Direct dangerous scheme.
    if re.search(
        r"(?:javascript|data|vbscript)\s*:",
        output,
        re.IGNORECASE
    ):
        return True

    # Extracted URLs.
    for value in extract_urls(channel, output):

        parsed = urlparse(
            normalize_url(value)
        )

        if parsed.scheme:

            if parsed.scheme.lower() not in {
                "http",
                "https"
            }:
                return True

    return False


# ============================================================
# EXTERNAL EXFILTRATION
# ============================================================

def external_exfiltration(channel: str, output: str):

    for value in extract_urls(channel, output):

        value = value.strip()

        # Relative URL is safe.
        if not value.startswith("//"):

            parsed = urlparse(value)

            if not parsed.scheme:
                continue

        else:

            parsed = urlparse(
                normalize_url(value)
            )

        # Dangerous schemes are handled separately.
        if parsed.scheme.lower() not in {
            "http",
            "https"
        }:
            continue

        # Compare hostname ONLY.
        hostname = parsed.hostname

        if hostname is None:
            return True

        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ============================================================
# HTML RULES
# ============================================================

def html_reason(output: str):

    # 1. SCRIPT_TAG

    if re.search(
        r"<\s*(script|iframe|object|embed)\b",
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

    if dangerous_scheme("html", output):
        return "DANGEROUS_SCHEME"


    # 4. EXTERNAL_EXFIL

    if external_exfiltration("html", output):
        return "EXTERNAL_EXFIL"


    return None


# ============================================================
# MARKDOWN RULES
# ============================================================

def markdown_reason(output: str):

    if dangerous_scheme("markdown", output):
        return "DANGEROUS_SCHEME"

    if external_exfiltration("markdown", output):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# URL RULES
# ============================================================

def url_reason(output: str):

    if dangerous_scheme("url", output):
        return "DANGEROUS_SCHEME"

    if external_exfiltration("url", output):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# SQL RULES
# ============================================================

def sql_reason(output: str):

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

    if re.search(
        r"\bunion\b",
        output,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        output,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"

    return None


# ============================================================
# SHELL RULES
# ============================================================

def shell_reason(output: str):

    if any(c in output for c in ";&|`<>"):
        return "SHELL_METACHAR"

    if "$(" in output:
        return "SHELL_METACHAR"

    if "${" in output:
        return "SHELL_METACHAR"

    return None


# ============================================================
# CHANNEL DISPATCH
# ============================================================

def check_channel(channel: str, output: str):

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
def sanitize_output(request: SanitizeRequest):

    channel = request.channel
    output = request.output


    # ========================================================
    # RULE 1: INVALID_SCHEMA
    # ========================================================

    if channel not in ALLOWED_CHANNELS:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }


    # ========================================================
    # RULE 2: ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded
        )

        if decoded_reason is not None:

            return {
                "safe": False,
                "reason": "ENCODED_PAYLOAD"
            }


    # ========================================================
    # RULE 3: ORIGINAL OUTPUT
    # ========================================================

    reason = check_channel(
        channel,
        output
    )

    if reason is not None:

        return {
            "safe": False,
            "reason": reason
        }


    # ========================================================
    # SAFE
    # ========================================================

    return {
        "safe": True,
        "reason": "SAFE"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def health():

    return {
        "status": "ok"
    }