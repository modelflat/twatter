#!/usr/bin/env python3
import json
import logging
import re

from functools import lru_cache
from typing import Dict, Optional, NamedTuple, Any, Callable

from requests import Session


USER_AGENT = "Mozilla/5.0"

BASE_URL = "https://twitter.com"
COOKIE_DOMAIN = ".twitter.com"
LOGIN_FLOW_URL = "https://api.twitter.com/1.1/onboarding/task.json"
GUEST_TOKEN_ACTIVATE_URL = "https://api.twitter.com/1.1/guest/activate.json"

RE_MAIN_JS_URL = re.compile(r"src=\"(http[^ ]+main.\w+.js)\"")
RE_OAUTH_TOKEN_MAIN_JS = re.compile(r"\"(AAAAAA[^,.\s\"]{80,})\"")


StrDict = Dict[str, str]
AnyDict = Dict[str, Any]
FnDict = Dict[str, Callable]


LOG = logging.getLogger("twatter")


class LoginFlowRequest(NamedTuple):
    data: AnyDict
    query: Optional[StrDict] = None

    def as_dict(self) -> AnyDict:
        return dict(json=self.data, params=self.query or dict())


class LoginFlowResponse(NamedTuple):
    token: str
    subtasks: Dict[str, AnyDict]

    @staticmethod
    def from_response(raw: AnyDict) -> 'LoginFlowResponse':
        return LoginFlowResponse(
            token=raw["flow_token"],
            subtasks={subtask.pop("subtask_id"): subtask for subtask in raw["subtasks"]}
        )


class LoggedInUser(NamedTuple):
    user_id: str
    oauth_token: str
    guest_token: str
    auth_token: str
    csrf_token: str


def login_flow_start(**_) -> LoginFlowRequest:
    return LoginFlowRequest(
        data={
            "input_flow_data": {
                "flow_context": {
                    "debug_overrides": {},
                    "start_location": {
                        "location": "unknown"
                    },
                },
            },
            "subtask_versions": {
                "action_list": 2,
                "alert_dialog": 1,
                "app_download_cta": 1,
                "check_logged_in_account": 1,
                "choice_selection": 3,
                "contacts_live_sync_permission_prompt": 0,
                "cta": 7,
                "email_verification": 2,
                "end_flow": 1,
                "enter_date": 1,
                "enter_email": 2,
                "enter_password": 5,
                "enter_phone": 2,
                "enter_recaptcha": 1,
                "enter_text": 5,
                "enter_username": 2,
                "generic_urt": 3,
                "in_app_notification": 1,
                "interest_picker": 3,
                "js_instrumentation": 1,
                "menu_dialog": 1,
                "notifications_permission_prompt": 2,
                "open_account": 2,
                "open_home_timeline": 1,
                "open_link": 1,
                "phone_verification": 4,
                "privacy_options": 1,
                "security_key": 3,
                "select_avatar": 4,
                "select_banner": 2,
                "settings_list": 7,
                "show_code": 1,
                "sign_up": 2,
                "sign_up_review": 4,
                "tweet_selection_urt": 1,
                "update_users": 1,
                "upload_media": 1,
                "user_recommendations_list": 4,
                "user_recommendations_urt": 1,
                "wait_spinner": 3,
                "web_modal": 1
            }
        },
        query={
            "flow_name": "login"
        }
    )


def login_flow_js_instrumentation(token: str, **_) -> LoginFlowRequest:
    return LoginFlowRequest({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginJsInstrumentationSubtask",
            "js_instrumentation": {
                "response": "{}",
                "link": "next_link",
            },
        }]
    })


def login_flow_account_duplication_check(token: str, **_) -> LoginFlowRequest:
    return LoginFlowRequest({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "AccountDuplicationCheck",
            "check_logged_in_account": {
                "link": "AccountDuplicationCheck_false",
            },
        }],
    })


def login_flow_enter_username(token: str, username: str, **_) -> LoginFlowRequest:
    return LoginFlowRequest({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginEnterUserIdentifierSSO",
            "settings_list": {
                "setting_responses": [{
                    "key": "user_identifier",
                    "response_data": {
                        "text_data": {
                            "result": username
                        },
                    },
                }],
                "link": "next_link",
            },
        }]
    })


def login_flow_enter_password(token: str, password: str, **_) -> LoginFlowRequest:
    return LoginFlowRequest({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginEnterPassword",
            "enter_password": {
                "password": password,
                "link": "next_link"
            }
        }]
    })


def login_flow_enter_email(token: str, email: str, **_) -> LoginFlowRequest:
    return LoginFlowRequest({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginAcid",
            "enter_text": {
                "text": email,
                "link": "next_link"
            },
        }],
    })


def execute_login_flow_request(http: Session, headers: StrDict, step: LoginFlowRequest) -> LoginFlowResponse:
    response = http.post(LOGIN_FLOW_URL, headers=headers, **step.as_dict())
    response.raise_for_status()
    result = response.json()
    if result.get("status") != "success":
        raise RuntimeError(f"failed to submit login flow step: {response.text}")
    return LoginFlowResponse.from_response(result)


def run_login_flow(
    http: Session,
    oauth_token: str,
    guest_token: str,
    email: str,
    username: str,
    password: str,
    custom_step_handlers: Optional[FnDict],
) -> AnyDict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {oauth_token}",
        "X-Guest-Token": guest_token,
        "X-Twitter-Active-User": "yes",
    }
    flow_steps = dict(
        LoginSuccessSubtask=None,
        LoginJsInstrumentationSubtask=login_flow_js_instrumentation,
        AccountDuplicationCheck=login_flow_account_duplication_check,
        LoginEnterUserIdentifierSSO=login_flow_enter_username,
        LoginEnterPassword=login_flow_enter_password,
        LoginAcid=login_flow_enter_email,
    )
    flow_steps.update(custom_step_handlers or dict())
    step_id = 1
    step_name = "Start"
    step = login_flow_start
    response = None
    next_step_name = None
    context = dict(email=email, username=username, password=password)
    while step is not None:
        request = step(**context)
        response = execute_login_flow_request(http, headers, request)
        context["response"], context["token"] = response, response.token  # type: ignore
        next_step_name, step = next(filter(lambda el: el[0] in response.subtasks, flow_steps.items()))  # type: ignore
        LOG.debug("[%s] ✅ %s -> %s", step_id, step_name, next_step_name)
        step_id += 1
        step_name = next_step_name  # type: ignore
    return response.subtasks[next_step_name]


def get_oauth_token(http: Session) -> str:
    """
    Retrieves publicly available oauth_token from Twitter frontend source code.
    """
    # this is needed to initiate Twitter cookies, so we do this request every time.
    home_page = http.get(BASE_URL)
    home_page.raise_for_status()

    @lru_cache()
    def _get_token(main_js_url):
        # this request can safely be cached, as token from the file can only change if the url changes.
        main_js_source = http.get(main_js_url)
        main_js_source.raise_for_status()
        return next(RE_OAUTH_TOKEN_MAIN_JS.finditer(main_js_source.text)).group(1)

    main_js_url = next(RE_MAIN_JS_URL.finditer(home_page.text)).group(1)
    return _get_token(main_js_url)


def get_guest_token(http: Session, oauth_token: str, guest_id: Optional[str] = None) -> str:
    """
    Exchanges `guest_id` for guest_token.
    If guest_id is not provided, it is assumed to be already present in session cookies.
    """
    if guest_id is not None:
        http.cookies.set("guest_id", guest_id, domain=COOKIE_DOMAIN)
    response = http.post(
        GUEST_TOKEN_ACTIVATE_URL,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {oauth_token}",
        },
    )
    response.raise_for_status()
    return response.json().get("guest_token")


def login_ex(
    http: Session,
    email: str,
    username: str,
    password: str,
    custom_step_handlers: Optional[FnDict] = None,
) -> LoggedInUser:
    """
    Logs into Twitter using provided credentials. Additional handlers for login flow can be provided.
    """
    oauth_token = get_oauth_token(http)
    LOG.debug("✅ oauth_token = %s", oauth_token)
    guest_token = get_guest_token(http, oauth_token)
    LOG.debug("✅ guest_token = %s", guest_token)
    success_subtask = run_login_flow(http, oauth_token, guest_token, email, username, password, custom_step_handlers)
    LOG.debug("✅ login flow returned %s", json.dumps(success_subtask))
    user_id = str(success_subtask["open_account"]["user"]["id_str"])
    cookies = http.cookies.get_dict(domain=COOKIE_DOMAIN)
    auth_token = cookies["auth_token"]
    csrf_token = cookies["ct0"]
    LOG.debug("✅ auth_token = %s, csrf_token (ct0) = %s", auth_token, csrf_token)
    return LoggedInUser(user_id, oauth_token, guest_token, auth_token, csrf_token)


def login(email: str, username: str, password: str) -> LoggedInUser:
    with Session() as http:
        http.headers["User-Agent"] = USER_AGENT
        return login_ex(http, email, username, password)


def _cli_main():
    import os
    import sys
    logging.basicConfig(level="DEBUG", stream=sys.stderr)
    result = login(*os.environ["TWITTER_LOGIN_DATA"].split(":", maxsplit=3))
    print(json.dumps(result._asdict(), indent=2))


if __name__ == "__main__":
    _cli_main()
