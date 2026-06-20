"""Pure-HTTP zhixuewang login with Geetest v4 slide-only captcha bypass.

Login chain (8 steps, 2 captcha solves):
  1. GET  /login/getServiceUrl                         -> casUrl, serviceUrl
  2. Solve Geetest v4 slide captcha #1 (fixed captcha_id)
  3. POST /edition/login?from=wap_login                 -> userId, captchaId2
     (jQuery-style bracketed thirdCaptchaExtInfo[field]=value encoding)
  4. Solve Geetest v4 slide captcha #2 (fixed captcha_id)
  5. GET  {casUrl}/v1/getSingleAt (JSONP)               -> at, service
     (RSA R2/P encrypted password, thirdCaptchaParam as JSON)
  6a. GET  {service} (open.changyan.com/sso/atLogin?at=...)
     -> sets CASTGC cookie, redirects to open.changyan.com/sso/login
  6b. GET  open.changyan.com/sso/login?...               -> st (service ticket)
  6c. POST {serviceUrl} action=login&ticket={st}         -> final session cookies
  7. POST /loginSuccess/ {userId}                        -> complete local login

Author: JerryPig678
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Dict
from urllib.parse import urlencode, quote

from curl_cffi import requests as curl_requests

from crypto import rc4_encrypt_password, rsa_encrypt_r2p
from geeked import Geeked

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

ZHIXUE_BASE_URL = "https://www.zhixue.com"

APP_ID = "zx-container-client"
CLIENT = "web"
CAPTCHA_TYPE = "third"
ACCOUNT_VERSION = "v2"
LOGIN_TYPE = "loginByNormal"
_ENCODE_TYPE = "R2/P"

# iFlytek's Geetest instance for zhixuewang
_GEETEST_BASE_URL = "https://xunfei.geetest.com"
# Fixed captcha_id for the pre-login step
_FIXED_CAPTCHA_ID = "a6474422e78e5bb048082ec77d141068"

_MAX_SLIDE_RETRIES = 30
_RETRY_DELAY_SEC = 0.5

# Include ALL 5 fields from Geetest seccode
_VALIDATE_KEYS = {"captcha_id", "lot_number", "pass_token", "captcha_output", "gen_time"}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class LoginError(RuntimeError):
    """Raised when the login flow cannot complete."""


def _jsonp_parse(text: str) -> dict:
    text = text.strip()
    # Try plain JSON first
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try JSONP callback: callback({...})
    start = text.find("(")
    end = text.rfind(")")
    if start != -1 and end != -1 and end > start:
        inner = text[start + 1 : end]
        try:
            return json.loads(inner)
        except (json.JSONDecodeError, ValueError):
            pass

    # Try JS template literal
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        inner = text[brace_start : brace_end + 1]
        inner = inner.replace("\\", "")
        try:
            return json.loads(inner)
        except (json.JSONDecodeError, ValueError):
            pass

    raise ValueError(f"JSONP parse failed: {text[:500]}")


def _jquery_encode(params: dict, prefix: str = "") -> str:
    """Encode a nested dict as jQuery.param() would (bracket notation)."""
    parts = []
    for k, v in params.items():
        full_key = f"{prefix}[{k}]" if prefix else k
        if isinstance(v, dict):
            parts.append(_jquery_encode(v, full_key))
        else:
            parts.append(f"{quote(full_key)}={quote(str(v))}")
    return "&".join(parts)


def _filter_validate(result: dict) -> dict:
    """Keep only the standard Geetest v4 validate fields."""
    return {k: v for k, v in result.items() if k in _VALIDATE_KEYS}


# ---------------------------------------------------------------------------
# captcha solver
# ---------------------------------------------------------------------------


def _solve_slide_only(captcha_id: str = "", print_fn=None) -> dict:
    """Get a slide-type captcha solution. Retries until slide appears."""
    _cid = captcha_id or _FIXED_CAPTCHA_ID

    def _log(msg: str) -> None:
        if print_fn:
            print_fn(msg)

    for attempt in range(1, _MAX_SLIDE_RETRIES + 1):
        gk = Geeked(_cid, base_url=_GEETEST_BASE_URL)
        gk.risk_type = "slide"
        gk.challenge = str(uuid.uuid4())
        gk.callback = Geeked.random()
        try:
            data = gk.load_captcha()
            detected = gk._detect_type(data)
            if detected != "slide":
                _log(f"  [captcha] attempt {attempt}: type={detected} (not slide), retrying...")
                time.sleep(_RETRY_DELAY_SEC)
                continue
            gk.lot_number = data["lot_number"]
            result = gk.submit_captcha(data)
            _log(f"  [captcha] attempt {attempt}: slide solved!")
            return result
        except Exception as exc:
            err_msg = str(exc)
            if "dddd_service" in err_msg:
                time.sleep(_RETRY_DELAY_SEC)
                continue
            if "connect_error" in err_msg or "ConnectionError" in err_msg or "RemoteDisconnected" in err_msg:
                _log(f"  [captcha] attempt {attempt}: connection error, retrying...")
                time.sleep(_RETRY_DELAY_SEC * 2)
                continue
            if attempt >= _MAX_SLIDE_RETRIES:
                raise LoginError(f"Captcha solve failed ({_MAX_SLIDE_RETRIES} retries): {exc}") from exc
            _log(f"  [captcha] attempt {attempt}: error: {err_msg[:80]}, retrying...")
            time.sleep(_RETRY_DELAY_SEC)
    raise LoginError(f"Failed to get slide-type captcha ({_MAX_SLIDE_RETRIES} retries)")


# ---------------------------------------------------------------------------
# main login orchestrator
# ---------------------------------------------------------------------------


def http_login(username: str, password: str, timeout: int = 60, print_fn=None) -> Dict[str, str]:
    """Pure-HTTP login orchestrator. Returns a cookie dict on success.

    Args:
        username: zhixue.com student ID or phone number
        password: plaintext password
        timeout: request timeout in seconds
        print_fn: Optional callback(str) for progress messages.
    """

    def _log(msg: str) -> None:
        if print_fn:
            print_fn(msg)

    session = curl_requests.Session(impersonate="chrome124")
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/147.0.0.0 Safari/537.36"
            ),
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
    )
    session.timeout = timeout
    device_id = str(uuid.uuid4())

    # 0. Warm up: visit zhixue.com first to establish cookies
    _log("[0/8] Warming up zhixue.com session...")
    session.get(f"{ZHIXUE_BASE_URL}/wap_login.html")

    # 1. Get SSO URLs
    _log("[1/8] Getting SSO URLs...")
    svc = session.get(f"{ZHIXUE_BASE_URL}/login/getServiceUrl").json()
    cas_url: str = svc["casUrl"].rstrip("/")
    service_url: str = svc["serviceUrl"]

    # 2. Solve captcha #1 for pre-login
    _log("[2/8] Solving captcha #1 (pre-login)...")
    captcha1 = _solve_slide_only(captcha_id=_FIXED_CAPTCHA_ID, print_fn=print_fn)
    validate1 = _filter_validate(captcha1)

    # 3. Pre-login (jQuery-style bracketed form encoding)
    _log("[3/8] Pre-login...")
    rc4_pwd = rc4_encrypt_password(password)
    body = _jquery_encode(
        {
            "loginName": username,
            "password": rc4_pwd,
            "description": "encrypt",
            "appId": APP_ID,
            "captchaType": CAPTCHA_TYPE,
            "deviceName": "web",
            "client": CLIENT,
            "deviceId": device_id,
            "thirdCaptchaExtInfo": validate1,
        }
    )
    resp = session.post(
        f"{ZHIXUE_BASE_URL}/edition/login?from=wap_login",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    pre = resp.json()
    if pre.get("result") != "success":
        raise LoginError(f"Pre-login failed: {pre.get('message', pre)}")
    user_id: str = pre["data"]["userId"]
    captcha_id2: str = pre["data"]["captchaId"]

    # 4. Solve captcha #2 for SSO
    _log(f"[4/8] Solving captcha #2 (SSO, server captchaId={captcha_id2})...")
    captcha2 = _solve_slide_only(captcha_id=_FIXED_CAPTCHA_ID, print_fn=print_fn)
    validate2 = _filter_validate(captcha2)

    # 5. SSO getSingleAt
    _log("[5/8] SSO authentication (getSingleAt)...")
    rsa_pwd = rsa_encrypt_r2p(password)
    third_param = json.dumps(validate2, ensure_ascii=False)

    params = {
        "appId": APP_ID,
        "client": CLIENT,
        "mac": device_id,
        "service": service_url,
        "extInfo": json.dumps({"deviceId": device_id}),
        "type": LOGIN_TYPE,
        "username": username,
        "password": rsa_pwd,
        "encodeType": _ENCODE_TYPE,
        "encode": "true",
        "key": "auto",
        "captchaId": captcha_id2,
        "captchaType": CAPTCHA_TYPE,
        "thirdCaptchaParam": third_param,
        "version": ACCOUNT_VERSION,
    }
    full_url = f"{cas_url}/v1/getSingleAt?{urlencode(params)}"
    resp = session.get(full_url)
    at_data = _jsonp_parse(resp.text)
    if at_data.get("code") != "success" or not at_data.get("data", {}).get("at"):
        raise LoginError(
            f"getSingleAt failed: {json.dumps(at_data, ensure_ascii=False)[:500]}"
        )
    at_token = at_data['data']['at']
    at_service = at_data['data'].get('service', '')

    # 6. SSO: get ST via atLogin, then exchange for session cookies
    _log("[6/8] SSO: getting ST (via atLogin)...")
    session.headers.pop("X-Requested-With", None)
    session.headers["Referer"] = f"{ZHIXUE_BASE_URL}/"
    session.headers["Accept"] = "*/*"

    # Step 6a: Visit atLogin endpoint to get CASTGC cookie
    if at_service:
        resp = session.get(at_service, allow_redirects=True)
    else:
        resp = session.get(
            f"{cas_url}/login?service={quote(service_url, safe='')}",
            allow_redirects=True,
        )

    # Step 6b: Get ST from open.changyan.com/sso/login
    resp = session.get(
        f"https://open.changyan.com/sso/login?sso_from=zhixuesso&service={quote(service_url, safe='')}",
        allow_redirects=False,
    )
    st_data = _jsonp_parse(resp.text.strip())

    # Step 6c: Exchange ST for session cookies
    if st_data.get("code") == 1001 and st_data.get("data", {}).get("st"):
        st = st_data["data"]["st"]
        session.headers["X-Requested-With"] = "XMLHttpRequest"
        session.headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
        session.post(service_url, data={"action": "login", "ticket": st})

    # Restore headers
    session.headers["X-Requested-With"] = "XMLHttpRequest"
    session.headers["Accept"] = "application/json, text/javascript, */*; q=0.01"

    # 7. Complete login
    _log("[7/8] Calling loginSuccess...")
    session.post(f"{ZHIXUE_BASE_URL}/loginSuccess/", data={"userId": user_id})

    # 8. Build cookie dict
    cookies: Dict[str, str] = {}
    for cookie in session.cookies.jar:
        if cookie.domain and "zhixue.com" in cookie.domain:
            cookies[cookie.name] = cookie.value
    for cookie in session.cookies.jar:
        if cookie.name not in cookies:
            cookies[cookie.name] = cookie.value
    if not cookies.get("loginUserName"):
        cookies["loginUserName"] = username

    _log(f"Login success! Got {len(cookies)} cookies")
    return cookies
