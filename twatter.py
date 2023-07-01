#!/usr/bin/env python3

import json
import logging
import os
import re
import sys
import time

from datetime import datetime, timezone
from functools import lru_cache
from typing import Callable, Dict, Optional, NamedTuple, Any, Tuple

from requests import HTTPError, Session


USER_AGENT = "Mozilla/5.0"

BASE_URL = "https://twitter.com"
COOKIE_DOMAIN = ".twitter.com"
LOGIN_FLOW_URL = "https://api.twitter.com/1.1/onboarding/task.json"
GUEST_TOKEN_ACTIVATE_URL = "https://api.twitter.com/1.1/guest/activate.json"

RE_MAIN_JS_URL = re.compile(r"src=\"(http[^ ]+main.\w+.js)\"")
RE_OAUTH_TOKEN_MAIN_JS = re.compile(r"\"(AAAAAA[^,.\s\"]{80,})\"")


StrDict = Dict[str, str]
AnyDict = Dict[str, Any]


LOG = logging.getLogger("twatter")

try:
    from googleapiclient.discovery import build  # type: ignore
    from google.oauth2.credentials import Credentials  # type: ignore
    from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
    from google.auth.transport.requests import Request  # type: ignore

    class Gmail:
        SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

        def __init__(self, gmail_tokens_path: str):
            creds = Credentials.from_authorized_user_file(gmail_tokens_path, scopes=self.SCOPES)
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with open(gmail_tokens_path, "w") as f:
                    f.write(creds.to_json())
            if not creds.valid:
                raise RuntimeError(
                    "unable to perform GCP auth authomatically. "
                    "use `create_authorized_credentials` to create tokens manually"
                )
            self.messages = build("gmail", "v1", credentials=creds).users().messages()

        def get_latest_message(self, query: str) -> Optional[Tuple[datetime, str]]:
            messages = self.messages.list(userId="me", q=query).execute().get("messages", [])
            if not messages:
                return None

            latest_message = self.messages.get(userId="me", id=messages[0]["id"]).execute()
            headers = latest_message["payload"]["headers"]
            date = next(filter(lambda h: h["name"] == "Date", headers))["value"]
            date_parsed = datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z")
            subject = next(filter(lambda h: h["name"] == "Subject", headers))["value"]
            return date_parsed.astimezone(), subject

        def poll_for_message_after(self, query: str, after: datetime, retries: int, delay: int) -> str:
            LOG.debug("polling for messages after %s", str(after))
            for attempt in range(1, retries + 1):
                time.sleep(delay)
                latest = self.get_latest_message(query)
                if latest is None or latest[0] < after:
                    LOG.debug("[attempt %s] no new mail (latest = %s)", attempt, str(latest))
                else:
                    LOG.debug("got new mail: %s", latest[1])
                    return latest[1]
            if latest is not None:
                LOG.debug("time is out; returning stale mail from %s: %s", str(latest[0]), latest[1])
                return latest[1]
            raise RuntimeError("retrieving mail: time is out!")

        @classmethod
        def create_tokens(cls, credentials_path: str, tokens_output_path: Optional[str] = None) -> Credentials:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes=cls.SCOPES)
            credentials = flow.run_local_server(port=0)
            if tokens_output_path is not None:
                with open(tokens_output_path, "w") as f:
                    f.write(credentials.to_json())
            return credentials

except ImportError as e:
    Gmail = None  # type: ignore
    LOG.warning(f"gmail integration won't be available because: {e}")


class LoggedInUser(NamedTuple):
    user_id: str
    oauth_token: str
    guest_token: str
    auth_token: str
    csrf_token: str


class LoginFlowRequest(NamedTuple):
    data: AnyDict
    query: Optional[StrDict] = None

    def as_dict(self) -> AnyDict:
        return dict(json=self.data, params=self.query or dict())

    @staticmethod
    def start() -> 'LoginFlowRequest':
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

    @staticmethod
    def subtask(token: str, body: AnyDict) -> 'LoginFlowRequest':
        return LoginFlowRequest({"flow_token": token, "subtask_inputs": [body]})


class LoginFlowResponse(NamedTuple):
    token: str
    subtasks: Dict[str, AnyDict]

    @staticmethod
    def from_response(raw: AnyDict) -> 'LoginFlowResponse':
        return LoginFlowResponse(
            token=raw["flow_token"],
            subtasks={subtask.pop("subtask_id"): subtask for subtask in raw["subtasks"]}
        )


class LoginFlow:
    """
    Implementation of a Twitter login flow.

    Twitter login flow consists of multiple steps. On each step, client has to perform a task and send the result back
    to the server.
    """

    def __init__(self, http: Session, oauth_token: str, guest_token: str):
        self.http = http
        self.oauth_token = oauth_token
        self.guest_token = guest_token
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {oauth_token}",
            "X-Guest-Token": guest_token,
            "X-Twitter-Active-User": "yes",
        }

    def step_js_instrumentation(self, token: str, **_) -> LoginFlowRequest:
        return LoginFlowRequest.subtask(token, {
            "subtask_id": "LoginJsInstrumentationSubtask",
            "js_instrumentation": {
                "response": "{}",
                "link": "next_link",
            },
        })

    def step_account_duplication_check(self, token: str, **_) -> LoginFlowRequest:
        return LoginFlowRequest.subtask(token, {
            "subtask_id": "AccountDuplicationCheck",
            "check_logged_in_account": {
                "link": "AccountDuplicationCheck_false",
            },
        })

    def step_enter_username(self, token: str, username: str, **_) -> LoginFlowRequest:
        return LoginFlowRequest.subtask(token, {
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
        })

    def step_enter_password(self, token: str, password: str, **_) -> LoginFlowRequest:
        return LoginFlowRequest.subtask(token, {
            "subtask_id": "LoginEnterPassword",
            "enter_password": {
                "password": password,
                "link": "next_link"
            }
        })

    def step_acid(self, token: str, email: str, response: LoginFlowResponse, **context) -> LoginFlowRequest:
        this_subtask = response.subtasks["LoginAcid"]
        task_type = this_subtask["enter_text"]["keyboard_type"]
        if task_type == "email":
            response_text = email
        elif task_type == "text":
            response_text = self.handle_acid_email_code(email, **context)
        else:
            raise RuntimeError(f"unknown LoginAcid type: '{task_type}'. Subtask: {json.dumps(this_subtask, indent=2)}")
        return LoginFlowRequest.subtask(token, {
            "subtask_id": "LoginAcid",
            "enter_text": {
                "text": response_text,
                "link": "next_link"
            },
        })

    def handle_acid_email_code(self, email: str, **context) -> str:
        if Gmail is None:
            raise RuntimeError(
                "gmail integration is not available! you'll need to install google's libraries for that; "
                "see requirements.txt in the repo"
            )
        LOG.debug("trying to retrieve confirmation code from %s", email)
        gmail = Gmail(context["gmail_tokens_path"])
        message = gmail.poll_for_message_after(
            query="from:info@twitter.com (Your Twitter confirmation code is) ",
            after=context["ts"],
            retries=context.get("gmail_retries", 6),
            delay=context.get("gmail_delay", 10),
        )
        return message.split()[-1]

    def get_steps(self) -> Dict[str, Optional[Callable]]:
        return dict(
            LoginSuccessSubtask=None,
            LoginJsInstrumentationSubtask=self.step_js_instrumentation,
            AccountDuplicationCheck=self.step_account_duplication_check,
            LoginEnterUserIdentifierSSO=self.step_enter_username,
            LoginEnterPassword=self.step_enter_password,
            LoginAcid=self.step_acid,
        )

    def execute_request(self, step: LoginFlowRequest) -> LoginFlowResponse:
        response = self.http.post(LOGIN_FLOW_URL, headers=self.headers, **step.as_dict())
        try:
            response.raise_for_status()
        except HTTPError as e:
            LOG.error(f"failed to perform step: {json.dumps(step.as_dict())}")
            LOG.error(f"twitter's response: {response.status_code} {response.text}")
            raise e
        result = response.json()
        if result.get("status") != "success":
            raise RuntimeError(f"failed to submit login flow step: {response.text}")
        return LoginFlowResponse.from_response(result)

    def run(self, email: str, username: str, password: str, **context) -> LoggedInUser:
        steps = self.get_steps()
        step_id = 1
        step_name = "Start"
        step = lambda **_: LoginFlowRequest.start()  # noqa
        response = None
        next_step_name = None
        context = dict(email=email, username=username, password=password, **context)
        context["ts"] = datetime.now(timezone.utc)
        while step is not None:
            response = self.execute_request(step(**context))
            context["response"] = response
            context["token"] = response.token
            next_step_name, step = next(filter(lambda el: el[0] in response.subtasks, steps.items()))  # type: ignore
            LOG.debug("[%s] ✅ %s -> %s", step_id, step_name, next_step_name)
            step_id += 1
            step_name = next_step_name  # type: ignore
        success_subtask = response.subtasks[next_step_name]
        LOG.debug("✅ login flow ended with %s", json.dumps(success_subtask))
        user_id = str(success_subtask["open_account"]["user"]["id_str"])
        cookies = self.http.cookies.get_dict(domain=COOKIE_DOMAIN)
        auth_token = cookies["auth_token"]
        LOG.debug("✅ auth_token = %s", auth_token)
        csrf_token = cookies["ct0"]
        LOG.debug("✅ csrf_token (ct0) = %s", csrf_token)
        return LoggedInUser(user_id, self.oauth_token, self.guest_token, auth_token, csrf_token)

    @classmethod
    def create(cls, http: Session) -> 'LoginFlow':
        oauth_token = get_oauth_token(http)
        LOG.debug("✅ oauth_token = %s", oauth_token)
        guest_token = get_guest_token(http, oauth_token)
        LOG.debug("✅ guest_token = %s", guest_token)
        return LoginFlow(http, oauth_token, guest_token)


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


def login(email: str, username: str, password: str, **context) -> LoggedInUser:
    """
    Logs into Twitter using provided credentials.
    """
    with Session() as http:
        http.headers["User-Agent"] = USER_AGENT
        return LoginFlow.create(http).run(email, username, password, **context)


def _cli_login(args):
    twitter_credentials = os.environ["TWITTER_LOGIN_DATA"].split(":", maxsplit=3)
    result = login(
        *twitter_credentials,
        gmail_tokens_path=args.gmail_tokens_path
    )
    print(json.dumps(result._asdict(), indent=2))


def _cli_create_gmail_tokens(args):
    tokens = Gmail.create_tokens(args.credentials_path, args.tokens_output_path)
    print(tokens.to_json())


def _parse_args():
    import argparse
    parser = argparse.ArgumentParser("twatter")
    sub = parser.add_subparsers(dest="command_name")
    sub.required = True
    parser_login = sub.add_parser("login")
    parser_login.add_argument("--gmail-tokens-path", required=False, default="gmail_tokens.json")
    parser_login.set_defaults(command=_cli_login)
    parser_gmail = sub.add_parser("create-gmail-tokens")
    parser_gmail.add_argument("--credentials-path", type=str, required=False, default="gmail_credentials.json")
    parser_gmail.add_argument("--tokens-output-path", type=str, required=False, default="gmail_tokens.json")
    parser_gmail.set_defaults(command=_cli_create_gmail_tokens)
    return parser.parse_args()


def _main():
    logging.basicConfig(level="DEBUG", stream=sys.stderr)
    args = _parse_args()
    LOG.debug("args: %s", str(args))
    args.command(args)


if __name__ == "__main__":
    _main()
