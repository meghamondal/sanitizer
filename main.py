import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import unquote, urlparse

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictStr


app = FastAPI()


# ============================================================
# CONFIGURATION
# ============================================================

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

    return names.get(
        named.lower(),
        match.group(0)
    )


def decode_once(value):

    # 1. Percent escapes
    decoded = unquote(value)

    # 2. HTML entities
    decoded = HTML_ENTITY.sub(
        decode_html_entity,
        decoded
    )

    # 3. Unicode escapes
    decoded = UNICODE_ESCAPE.sub(
        lambda m: chr(int(m.group(1), 16)),
        decoded
    )

    return decoded


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(channel, output):

    # --------------------------------------------------------
    # URL CHANNEL
    # --------------------------------------------------------

    if channel == "url":
        return [output.strip()]


    # --------------------------------------------------------
    # HTML CHANNEL
    #
    # Values of quoted src= and href= attributes.
    # --------------------------------------------------------

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

        urls = []

        for match in pattern.finditer(output):

            value = match.group(1)

            if value is None:
                value = match.group(2)

            urls.append(value)

        return urls


    # --------------------------------------------------------
    # MARKDOWN CHANNEL
    #
    # Target inside ](...)
    # --------------------------------------------------------

    if channel == "markdown":

        pattern = re.compile(
            r"\]\((.*?)\)",
            re.DOTALL
        )

        urls = []

        for match in pattern.finditer(output):

            target = match.group(1).strip()

            if not target:
                continue

            # Markdown URL in angle brackets:
            # ](<https://example.com>)
            if target.startswith("<"):

                end = target.find(">")

                if end != -1:
                    target = target[1:end]

            else:

                # URL is the first whitespace-delimited token.
                target = target.split()[0]

            urls.append(target)

        return urls


    return []


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_protocol_relative(url):

    url = url.strip()

    if url.startswith("//"):
        return "https:" + url

    return url


# ============================================================
# DANGEROUS SCHEME
# ============================================================

DANGEROUS_SCHEME = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE
)


def has_dangerous_scheme(channel, output):

    # --------------------------------------------------------
    # Direct dangerous schemes anywhere in text.
    # --------------------------------------------------------

    if DANGEROUS_SCHEME.search(output):
        return True


    # --------------------------------------------------------
    # Schemes of extracted URLs.
    # --------------------------------------------------------

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


# ============================================================
# EXTERNAL EXFILTRATION
# ============================================================

def has_external_exfil(channel, output):

    for value in extract_urls(channel, output):

        value = value.strip()

        # ----------------------------------------------------
        # Protocol-relative URL is absolute.
        # ----------------------------------------------------

        if value.startswith("//"):

            parsed = urlparse(
                "https:" + value
            )

        else:

            parsed = urlparse(value)


        # ----------------------------------------------------
        # Relative references are allowed.
        # ----------------------------------------------------

        if not parsed.scheme:
            continue


        # ----------------------------------------------------
        # Non-http/https schemes are handled by
        # DANGEROUS_SCHEME.
        # ----------------------------------------------------

        if parsed.scheme.lower() not in {
            "http",
            "https"
        }:
            continue


        # ----------------------------------------------------
        # Compare hostname ONLY.
        # ----------------------------------------------------

        hostname = parsed.hostname

        if hostname is None:
            return True

        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ============================================================
# HTML STRUCTURE PARSER
# ============================================================

class HTMLSafetyParser(HTMLParser):

    def __init__(self):

        super().__init__(
            convert_charrefs=False
        )

        self.script_tag = False
        self.event_handler = False


    def handle_starttag(
        self,
        tag,
        attrs
    ):

        tag = tag.lower()

        # ----------------------------------------------------
        # SCRIPT_TAG
        # ----------------------------------------------------

        if tag in {
            "script",
            "iframe",
            "object",
            "embed"
        }:

            self.script_tag = True
            return


        # ----------------------------------------------------
        # EVENT_HANDLER
        #
        # Only actual HTML attributes beginning with "on"
        # are treated as event handlers.
        # ----------------------------------------------------

        for name, value in attrs:

            if name.lower().startswith("on"):

                self.event_handler = True
                return


def html_structure_reason(output):

    parser = HTMLSafetyParser()

    try:

        parser.feed(output)
        parser.close()

    except Exception:

        # Parser errors do not create a new reason.
        # Continue with the remaining deterministic checks.
        pass


    if parser.script_tag:
        return "SCRIPT_TAG"


    if parser.event_handler:
        return "EVENT_HANDLER"


    return None


# ============================================================
# HTML RULES
# ============================================================

def html_reason(output):

    # --------------------------------------------------------
    # 1. SCRIPT_TAG
    # 2. EVENT_HANDLER
    # --------------------------------------------------------

    structure_reason = html_structure_reason(
        output
    )

    if structure_reason is not None:
        return structure_reason


    # --------------------------------------------------------
    # 3. DANGEROUS_SCHEME
    # --------------------------------------------------------

    if has_dangerous_scheme(
        "html",
        output
    ):
        return "DANGEROUS_SCHEME"


    # --------------------------------------------------------
    # 4. EXTERNAL_EXFIL
    # --------------------------------------------------------

    if has_external_exfil(
        "html",
        output
    ):
        return "EXTERNAL_EXFIL"


    return None


# ============================================================
# MARKDOWN RULES
# ============================================================

def markdown_reason(output):

    # 1. DANGEROUS_SCHEME

    if has_dangerous_scheme(
        "markdown",
        output
    ):
        return "DANGEROUS_SCHEME"


    # 2. EXTERNAL_EXFIL

    if has_external_exfil(
        "markdown",
        output
    ):
        return "EXTERNAL_EXFIL"


    return None


# ============================================================
# URL RULES
# ============================================================

def url_reason(output):

    # 1. DANGEROUS_SCHEME

    if has_dangerous_scheme(
        "url",
        output
    ):
        return "DANGEROUS_SCHEME"


    # 2. EXTERNAL_EXFIL

    if has_external_exfil(
        "url",
        output
    ):
        return "EXTERNAL_EXFIL"


    return None


# ============================================================
# SQL RULES
# ============================================================

def sql_reason(output):

    # Single quote
    if "'" in output:
        return "SQL_METACHAR"


    # Double quote
    if '"' in output:
        return "SQL_METACHAR"


    # Semicolon
    if ";" in output:
        return "SQL_METACHAR"


    # SQL line comment
    if "--" in output:
        return "SQL_METACHAR"


    # SQL block comment
    if "/*" in output:
        return "SQL_METACHAR"


    # UNION
    if re.search(
        r"\bunion\b",
        output,
        re.IGNORECASE
    ):
        return "SQL_METACHAR"


    # OR 1=1
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

def shell_reason(output):

    # IMPORTANT:
    # There is NO SPACE in this string.
    #
    # Block exactly:
    # ; & | ` < >
    #

    if any(
        c in output
        for c in ";&|`<>"
    ):
        return "SHELL_METACHAR"


    # Command substitution
    if "$(" in output:
        return "SHELL_METACHAR"


    # Shell variable expansion
    if "${" in output:
        return "SHELL_METACHAR"


    return None


# ============================================================
# CHANNEL DISPATCH
# ============================================================

def channel_reason(
    channel,
    output
):

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
# MAIN ENDPOINT
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(
    request: SanitizeRequest
):

    channel = request.channel
    output = request.output


    # ========================================================
    # RULE 1: INVALID_SCHEMA
    # ========================================================

    if channel not in ALLOWED_CHANNELS:

        return unsafe_result(
            "INVALID_SCHEMA"
        )


    if len(output) > 20000:

        return unsafe_result(
            "INVALID_SCHEMA"
        )


    # ========================================================
    # RULE 2: ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = channel_reason(
            channel,
            decoded
        )

        if decoded_reason is not None:

            return unsafe_result(
                "ENCODED_PAYLOAD"
            )


    # ========================================================
    # RULE 3: ORIGINAL OUTPUT
    # ========================================================

    reason = channel_reason(
        channel,
        output
    )

    if reason is not None:

        return unsafe_result(
            reason
        )


    # ========================================================
    # SAFE
    # ========================================================

    return safe_result()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health():

    return {
        "status": "ok"
    }