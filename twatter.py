from collections import OrderedDict
import logging
import re

from typing import Dict, List, NamedTuple, Optional, Union

from requests import Session


USER_AGENT = "Mozilla/5.0"

BASE_URL = "https://twitter.com"
LOGIN_FLOW_URL = "https://api.twitter.com/1.1/onboarding/task.json"
GUEST_TOKEN_ACTIVATE_URL = "https://api.twitter.com/1.1/guest/activate.json"

RE_MAIN_JS_URL = re.compile(r"src=\"(http[^ ]+main.\w+.js)\"")
RE_OAUTH_TOKEN_MAIN_JS = re.compile(r"\"(AAAAAA[^,.\s\"]{80,})\"")


StrDict = Dict[str, str]
Json = Dict[str, Union['Json', List['Json'], str, float, int, None]]


class _LoginFlowStep(NamedTuple):
    data: Json
    query: Optional[StrDict] = None


class _LoginFlowStepResponse(NamedTuple):
    flow_token: str
    subtasks: Json


def _create_start_step() -> _LoginFlowStep:
    return _LoginFlowStep(
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


def _create_js_instrumentation_step(token: str) -> _LoginFlowStep:
    return _LoginFlowStep({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginJsInstrumentationSubtask",
            "js_instrumentation": {
                "response": "{}",
                "link": "next_link",
            },
        }]
    })


def _create_account_duplication_check_step(token: str) -> _LoginFlowStep:
    return _LoginFlowStep({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "AccountDuplicationCheck",
            "check_logged_in_account": {
                "link": "AccountDuplicationCheck_false",
            },
        }],
    })


def _create_enter_username_step(token: str, username: str) -> _LoginFlowStep:
    return _LoginFlowStep({
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


def _create_enter_password_step(token: str, password: str) -> _LoginFlowStep:
    return _LoginFlowStep({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginEnterPassword",
            "enter_password": {
                "password": password,
                "link": "next_link"
            }
        }]
    })


def _create_enter_email_step(token: str, email: str) -> _LoginFlowStep:
    return _LoginFlowStep({
        "flow_token": token,
        "subtask_inputs": [{
            "subtask_id": "LoginAcid",
            "enter_text": {
                "text": email,
                "link": "next_link"
            },
        }],
    })


def _submit_login_flow_step(http: Session, headers: StrDict, step: _LoginFlowStep) -> _LoginFlowStepResponse:
    response = http.post(LOGIN_FLOW_URL, headers=headers, params=step.query or {}, json=step.data)
    response.raise_for_status()
    result = response.json()
    if result.get('status') != 'success':
        raise RuntimeError(f'failed to submit login flow step: {response.text}')
    return _LoginFlowStepResponse(
        flow_token=result.get('flow_token'),
        subtasks={
            subtask.pop('subtask_id'): subtask
            for subtask in result.get('subtasks')
        },
    )


def extract_twitter_cookie(http: Session, name: str) -> Optional[str]:
    return http.cookies.get_dict(domain='.twitter.com').get(name)


def get_oauth_token(http: Session) -> str:
    home_page = http.get(BASE_URL)
    home_page.raise_for_status()
    main_js_url = next(RE_MAIN_JS_URL.finditer(home_page.text)).group(1)
    main_js_source = http.get(main_js_url)
    main_js_source.raise_for_status()
    return f'Bearer {next(RE_OAUTH_TOKEN_MAIN_JS.finditer(main_js_source.text)).group(1)}'


def get_guest_token(http: Session, oauth_token: str) -> str:
    activate_result = http.post(
        GUEST_TOKEN_ACTIVATE_URL,
        headers={
            'Content-Type': 'application/json',
            'Authorization': oauth_token
        }
    )
    activate_result.raise_for_status()
    return activate_result.json().get('guest_token')


def get_auth_token(
    http: Session,
    oauth_token: str,
    guest_token: str,
    username: str,
    password: str,
    email: str,
) -> str:
    headers = {
        'Content-Type': 'application/json',
        'Authorization': oauth_token,
        'X-Guest-Token': guest_token,
        'X-Twitter-Active-User': 'yes',
    }

    flow_steps = OrderedDict(
        LoginSuccessSubtask=None,
        LoginJsInstrumentationSubtask=lambda token: _create_js_instrumentation_step(token),
        AccountDuplicationCheck=lambda token: _create_account_duplication_check_step(token),
        LoginEnterUserIdentifierSSO=lambda token: _create_enter_username_step(token, username),
        LoginEnterPassword=lambda token: _create_enter_password_step(token, password),
        LoginAcid=lambda token: _create_enter_email_step(token, email),
    )

    step = 0
    step_name = 'Start'
    response = _submit_login_flow_step(http, headers, _create_start_step())
    while True:
        next_step_name, task = next(filter(lambda el: el[0] in response.subtasks, flow_steps.items()))
        logging.info(f'[{step}] ✅ {step_name} -> {next_step_name}')
        if task is None:
            break
        step += 1
        step_name, response = next_step_name, _submit_login_flow_step(http, headers, task(response.flow_token))
    return extract_twitter_cookie(http, 'auth_token')


def auth_ex(http: Session, username: str, password: str, email: str) -> StrDict:
    oauth_token = get_oauth_token(http)
    guest_token = get_guest_token(http, oauth_token)
    auth_token = get_auth_token(http, oauth_token, guest_token, username, password, email)
    csrf_token = extract_twitter_cookie(http, 'ct0')
    return dict(
        oauth_token=oauth_token,
        guest_token=guest_token,
        auth_token=auth_token,
        csrf_token=csrf_token
    )


def auth(username: str, password: str, email: str) -> StrDict:
    with Session() as http:
        http.headers['User-Agent'] = USER_AGENT
        return auth_ex(http, username, password, email)


def _cli_main():
    import os
    import json
    logging.basicConfig(level='INFO')
    email, username, password = os.environ['TWITTER_LOGIN_DATA'].split(':', maxsplit=3)
    print(json.dumps(auth(username, password, email)))


if __name__ == '__main__':
    _cli_main()
