"""
Overengineered web form to facilitate onboarding users to Google Workspace
"""

import logging
from base64 import b64encode
from hashlib import file_digest
from json import loads
from typing import Any, Dict, Union
from urllib.parse import urlparse, urlunparse
from uuid import UUID, uuid4

from authlib.integrations.flask_client import OAuth  # type: ignore

from celery import Celery, Task, shared_task

from flask import Flask, render_template, request, session
from flask.helpers import get_debug_flag, redirect, url_for

from flask_caching import Cache

from google.oauth2 import service_account

from googleapiclient.discovery import Resource, build  # type: ignore
from googleapiclient.errors import HttpError  # type: ignore

from hubspot import HubSpot  # type: ignore
from hubspot.settings.users.exceptions import NotFoundException  # type: ignore

from ldap3 import Connection, Server

from requests import delete, get, post, put

import sentry_sdk
from sentry_sdk import set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from slack_sdk import WebClient, WebhookClient
from slack_sdk.errors import SlackApiError
from slack_sdk.models.blocks import ActionsBlock, ButtonElement, ConfirmObject, SectionBlock
from slack_sdk.signature import SignatureVerifier

from werkzeug.exceptions import BadRequest, Unauthorized


def traces_sampler(sampling_context: Dict[str, Dict[str, str]]) -> bool:
    """
    Ignore ping events, sample all other events
    """
    try:
        request_uri = sampling_context["wsgi_environ"]["REQUEST_URI"]
    except KeyError:
        return False

    return request_uri != "/ping"


def init_celery(flask: Flask) -> Celery:
    """
    Initialize Celery
    """

    class FlaskTask(Task):  # type: ignore  # pylint: disable=abstract-method
        """
        Extend default Task class to have Flask context available

        https://flask.palletsprojects.com/en/stable/patterns/celery/
        """

        def __call__(self, *args, **kwargs):  # type: ignore
            with flask.app_context():
                return self.run(*args, **kwargs)

    new_celery_app = Celery("workspace_onboarding_ux", task_cls=FlaskTask)
    new_celery_app.config_from_object(flask.config, namespace="CELERY")
    new_celery_app.set_default()
    flask.extensions["celery"] = new_celery_app
    return new_celery_app


sentry_sdk.init(
    debug=get_debug_flag(),
    integrations=[
        FlaskIntegration(),
        PureEvalIntegration(),
    ],
    traces_sampler=traces_sampler,
    attach_stacktrace=True,
    max_request_body_size="always",
    in_app_include=[
        "workspace_onboarding_ux",
    ],
    profiles_sample_rate=1.0,
)

app = Flask(__name__)
app.config.from_prefixed_env()

celery_app = init_celery(app)

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    server_metadata_url=app.config["KEYCLOAK_METADATA_URL"],
    client_kwargs={"scope": "openid email profile"},
)

cache = Cache(app)
cache.clear()

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger("urllib3")
req_log.setLevel(logging.DEBUG)
req_log.propagate = True


def generate_subresource_integrity_hash(file: str) -> str:
    """
    Calculate the subresource integrity hash for a given file
    """
    with open(file[1:], "rb") as f:
        d = file_digest(f, "sha512")

    return "sha512-" + b64encode(d.digest()).decode("utf-8")


app.jinja_env.globals["calculate_integrity"] = generate_subresource_integrity_hash


def get_google_workspace_client() -> Resource:
    """
    Get a Google Workspace API client for manipulating users.
    """
    credentials = service_account.Credentials.from_service_account_info(  # type: ignore
        info=app.config["GOOGLE_SERVICE_ACCOUNT_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/admin.directory.user"],
        subject=app.config["GOOGLE_SUBJECT"],
    )

    directory = build(serviceName="admin", version="directory_v1", credentials=credentials)

    return directory.users()


@cache.cached(timeout=55, key_prefix="keycloak_access_token")
def get_keycloak_access_token() -> str:
    """
    Get an access token for Keycloak.
    """
    keycloak_access_token_response = post(
        url=app.config["KEYCLOAK_SERVER"] + "/realms/master/protocol/openid-connect/token",
        data={
            "client_id": app.config["KEYCLOAK_ADMIN_CLIENT_ID"],
            "client_secret": app.config["KEYCLOAK_ADMIN_CLIENT_SECRET"],
            "grant_type": "client_credentials",
        },
        timeout=(5, 5),
    )
    keycloak_access_token_response.raise_for_status()
    return keycloak_access_token_response.json()["access_token"]  # type: ignore


@cache.memoize()
def get_slack_user_id_by_email(email: str) -> Union[str, None]:
    """
    Wrapper for the users.lookupByEmail function to memoize responses
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    try:
        slack_response = slack.users_lookupByEmail(email=email)

        if slack_response.data["ok"]:  # type: ignore
            return slack_response.data["user"]["id"]  # type: ignore
    except SlackApiError:
        pass

    return None


@cache.memoize()
def get_slack_user_id(  # pylint: disable=too-many-return-statements,too-many-branches
    keycloak_user_id: str,
) -> Union[str, None]:
    """
    Get the Slack user ID for a given Keycloak or Ramp user
    """
    get_keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    keycloak_user = get_keycloak_user_response.json()

    if (
        "attributes" in keycloak_user
        and keycloak_user["attributes"] is not None
        and "googleWorkspaceAccount" in keycloak_user["attributes"]
        and keycloak_user["attributes"]["googleWorkspaceAccount"] is not None
        and len(keycloak_user["attributes"]["googleWorkspaceAccount"]) > 0
    ):
        slack_user_id = get_slack_user_id_by_email(
            keycloak_user["attributes"]["googleWorkspaceAccount"][0]
        )

        if slack_user_id is not None:
            return slack_user_id  # type: ignore

    if "email" in keycloak_user and keycloak_user["email"] is not None:
        slack_user_id = get_slack_user_id_by_email(keycloak_user["email"])

        if slack_user_id is not None:
            return slack_user_id  # type: ignore

    if "username" in keycloak_user and keycloak_user["username"] is not None:
        slack_user_id = get_slack_user_id_by_email(keycloak_user["username"] + "@gatech.edu")

        if slack_user_id is not None:
            return slack_user_id  # type: ignore

    if "username" in keycloak_user and keycloak_user["username"] is not None:
        apiary_user_response = get(
            url=app.config["APIARY_URL"] + "/api/v1/users/" + keycloak_user["username"],
            headers={
                "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
                "Accept": "application/json",
            },
            timeout=(5, 5),
        )

        if apiary_user_response.status_code == 200:
            apiary_user = apiary_user_response.json()["user"]

            if "gt_email" in apiary_user and apiary_user["gt_email"] is not None:
                slack_user_id = get_slack_user_id_by_email(apiary_user["gt_email"])

                if slack_user_id is not None:
                    return slack_user_id  # type: ignore

            if "gmail_address" in apiary_user and apiary_user["gmail_address"] is not None:
                slack_user_id = get_slack_user_id_by_email(apiary_user["gmail_address"])

                if slack_user_id is not None:
                    return slack_user_id  # type: ignore

            if "clickup_email" in apiary_user and apiary_user["clickup_email"] is not None:
                slack_user_id = get_slack_user_id_by_email(apiary_user["clickup_email"])

                if slack_user_id is not None:
                    return slack_user_id  # type: ignore

    with sentry_sdk.start_span(op="ldap.connect"):
        ldap = Connection(
            Server("whitepages.gatech.edu", connect_timeout=1),
            auto_bind=True,
            raise_exceptions=True,
            receive_timeout=1,
        )
    with sentry_sdk.start_span(op="ldap.search"):
        result = ldap.search(
            search_base="dc=whitepages,dc=gatech,dc=edu",
            search_filter="(uid=" + keycloak_user["username"] + ")",
            attributes=["mail"],
        )

    if result is True:
        for entry in ldap.entries:
            if "mail" in entry and entry["mail"] is not None and entry["mail"].value is not None:
                slack_user_id = get_slack_user_id_by_email(entry["mail"].value)

                if slack_user_id is not None:
                    return slack_user_id  # type: ignore

    return None


@cache.cached(key_prefix="slack_team_id")
def get_slack_team_id() -> str:
    """
    Get the team ID for the bot user, used for generating deep links

    https://docs.slack.dev/interactivity/deep-linking#open_a_channel
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.team_info()

    return slack_response["team"]["id"]  # type: ignore


@cache.memoize()
def get_slack_channel_name(channel_id: str) -> str:
    """
    Get the channel name for the given channel ID
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.conversations_info(channel=channel_id)

    return slack_response["channel"]["name"]  # type: ignore


@shared_task
def remove_eligible_role(keycloak_user_id: str) -> None:
    """
    Remove the eligible role from this user in Keycloak, after they are provisioned
    """
    remove_eligible_role_response = delete(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id
        + "/role-mappings/clients/"
        + app.config["KEYCLOAK_CLIENT_UUID"],
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
        json=[{"id": app.config["KEYCLOAK_CLIENT_ROLE_ELIGIBLE"], "name": "eligible"}],
    )
    remove_eligible_role_response.raise_for_status()


@shared_task
def import_user_to_org_chart(workspace_user_id: str) -> None:
    """
    Notify OrgChart after a user is added to Google Workspace
    """
    org_chart_response = post(
        url=app.config["ORG_CHART_NOTIFY_URL"],
        headers={
            "Accept": "application/json",
            "Authorization": "Token " + app.config["ORG_CHART_TOKEN"],
        },
        timeout=(5, 5),
        json={"google_workspace_user_id": workspace_user_id},
    )
    org_chart_response.raise_for_status()


@shared_task
def notify_slack_ineligible(keycloak_user_id: str) -> None:
    """
    Send a Slack notification to the central notifications channel when an ineligible user loads
    the form
    """
    if cache.get("slack_ineligible_message_" + keycloak_user_id) is not None:
        return

    get_keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    view_in_keycloak_button = ButtonElement(
        text="View in Keycloak",
        action_id="view_in_keycloak",
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_SERVER"]).scheme,
                urlparse(app.config["KEYCLOAK_SERVER"]).hostname,
                "/admin/master/console/",
                "",
                "",
                "/"
                + app.config["KEYCLOAK_REALM"]
                + "/users/"
                + str(keycloak_user_id)
                + "/settings",
            )
        ),
    )

    apiary_user_response = get(
        url=app.config["APIARY_URL"]
        + "/api/v1/users/"
        + get_keycloak_user_response.json()["username"],
        headers={
            "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )

    if apiary_user_response.status_code == 200:
        personal_pronoun_is = "they are"

        if (
            "gender" in apiary_user_response.json()["user"]
            and apiary_user_response.json()["user"]["gender"] is not None
        ):
            if str.lower(apiary_user_response.json()["user"]["gender"]) == "male":
                personal_pronoun_is = "he is"
            elif str.lower(apiary_user_response.json()["user"]["gender"]) == "female":
                personal_pronoun_is = "she is"

        actions = ActionsBlock(
            elements=[
                ButtonElement(
                    text="View in Apiary",
                    action_id="view_in_apiary",
                    url=app.config["APIARY_URL"]
                    + "/nova/resources/users/"
                    + str(apiary_user_response.json()["user"]["id"]),
                ),
                view_in_keycloak_button,
                ButtonElement(
                    text="Grant Eligibility in Keycloak",
                    action_id="grant_eligibility_in_keycloak",
                    value=keycloak_user_id,
                    style="primary",
                    confirm=ConfirmObject(
                        title="Grant Eligibility in Keycloak",
                        text="Are you sure you want to grant "
                        + get_keycloak_user_response.json()["firstName"]
                        + " eligibility for a Google Workspace account in Keycloak? If "
                        + personal_pronoun_is
                        + " in a leadership role, you should assign a role within Apiary instead.",  # noqa
                        confirm="Grant Eligibility",
                        deny="Cancel",
                    ),
                ),
            ]
        )
    elif apiary_user_response.status_code == 404:
        actions = ActionsBlock(
            elements=[
                view_in_keycloak_button,
            ]
        )
    else:
        actions = ActionsBlock(elements=[])
        apiary_user_response.raise_for_status()

    slack_user_id = get_slack_user_id(keycloak_user_id=keycloak_user_id)

    user_name = (
        get_keycloak_user_response.json()["firstName"]
        + " "
        + get_keycloak_user_response.json()["lastName"]
    )

    if slack_user_id is None:
        user_mention = user_name
    else:
        user_mention = f"<@{slack_user_id}>"

    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.chat_postMessage(
        channel=app.config["SLACK_NOTIFY_CHANNEL"],
        text=user_name
        + " logged in to the Google Workspace onboarding form, but isn't eligible for a Google Workspace account.",  # noqa
        blocks=[
            SectionBlock(
                text=user_mention
                + " logged in to the Google Workspace onboarding form, but isn't eligible for a Google Workspace account."  # noqa
            ),
            actions,
        ],
    )

    cache.set("slack_ineligible_message_" + keycloak_user_id, slack_response["ts"])


@shared_task
def notify_slack_account_created(keycloak_user_id: str) -> None:
    """
    Send Slack notifications to the central notifications channel when a new user is added
    to Google Workspace
    """
    keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    keycloak_user_response.raise_for_status()

    user_json = keycloak_user_response.json()

    new_user_slack_user_id = get_slack_user_id(keycloak_user_id=keycloak_user_id)

    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    new_user_name = user_json["firstName"] + " " + user_json["lastName"]

    if new_user_slack_user_id is None:
        new_user_mention = new_user_name
    else:
        new_user_mention = f"<@{new_user_slack_user_id}>"

    slack.chat_postMessage(
        channel=app.config["SLACK_NOTIFY_CHANNEL"],
        thread_ts=cache.get("slack_ineligible_message_" + keycloak_user_id),
        reply_broadcast=True,
        text=new_user_name + " joined Google Workspace!",
        blocks=[
            SectionBlock(
                text=new_user_mention + " joined Google Workspace!",
            ),
            ActionsBlock(
                elements=[
                    ButtonElement(
                        text="View in Google Workspace",
                        action_id="view_in_workspace",
                        url="https://www.google.com/a/robojackets.org/ServiceLogin?continue=https://admin.google.com/ac/search?query="  # noqa
                        + user_json["attributes"]["googleWorkspaceAccount"][0]
                        + "&tab=USERS",
                    )
                ]
            ),
        ],
    )


@shared_task(
    bind=True,
    max_retries=10,
    default_retry_delay=10,
    retry_backoff=True,
    retry_jitter=True,
    retry_backoff_max=60,
)
def invite_user_to_hubspot(self: Task, google_workspace_user_id: str) -> None:  # type: ignore
    """
    Invite a Google Workspace user to HubSpot
    """
    try:
        workspace_user = (
            get_google_workspace_client().get(userKey=google_workspace_user_id).execute()
        )
    except HttpError as e:
        if e.status_code == 404:
            raise self.retry(exc=e) from e

        raise e

    if not workspace_user["isMailboxSetup"]:
        raise self.retry(exc=Exception("Mailbox is not ready yet"))

    hubspot = HubSpot(access_token=app.config["HUBSPOT_ACCESS_TOKEN"])

    try:
        hubspot.settings.users.users_api.get_by_id(
            user_id=workspace_user["primaryEmail"], id_property="EMAIL"
        )
    except NotFoundException:
        hubspot.settings.users.users_api.create(
            user_provision_request={
                "firstName": workspace_user["name"]["givenName"],
                "lastName": workspace_user["name"]["familyName"],
                "email": workspace_user["primaryEmail"],
                "sendWelcomeEmail": True,
            }
        )


@app.get("/")
def index() -> Any:
    """
    Generates the main form, or messaging if the user shouldn't fill it out
    """
    if "user_state" not in session:
        return oauth.keycloak.authorize_redirect(url_for("login", _external=True))

    set_user(
        {
            "id": session["sub"],
            "ip_address": request.remote_addr,
        }
    )

    if session["user_state"] == "provisioned":
        return render_template(
            "provisioned.html",
            workspace_account=session["email_address"],
            slack_team_id=get_slack_team_id(),
            slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
            slack_support_channel_name=get_slack_channel_name(app.config["SLACK_SUPPORT_CHANNEL"]),
        )

    keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    keycloak_user_response.raise_for_status()

    user_json = keycloak_user_response.json()
    attributes = user_json["attributes"] if "attributes" in user_json else {}
    google_workspace_account = (
        attributes["googleWorkspaceAccount"][0]
        if "googleWorkspaceAccount" in attributes and len(attributes["googleWorkspaceAccount"]) > 0
        else None
    )

    if google_workspace_account is not None:
        workspace_user = (
            get_google_workspace_client().get(userKey=google_workspace_account).execute()
        )

        session["user_state"] = "provisioned"
        session["email_address"] = workspace_user["primaryEmail"]

        invite_user_to_hubspot.delay(workspace_user["id"])

        return render_template("provisioned.html", workspace_account=session["email_address"])

    if session["user_state"] == "ineligible":
        session.clear()
        return render_template(
            "ineligible.html",
            slack_team_id=get_slack_team_id(),
            slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
            slack_support_channel_name=get_slack_channel_name(app.config["SLACK_SUPPORT_CHANNEL"]),
        )

    return render_template(
        "form.html",
        elm_model={
            "firstName": session["first_name"],
            "lastName": session["last_name"],
            "emailAddress": session["email_address"],
        },
    )


@app.get("/login")
def login() -> Any:  # pylint: disable=too-many-branches
    """
    Handles the return from Keycloak and collects default values for the form
    """
    token = oauth.keycloak.authorize_access_token()

    userinfo = token["userinfo"]

    session["sub"] = userinfo["sub"]

    set_user(
        {
            "id": session["sub"],
            "ip_address": request.remote_addr,
        }
    )

    if "googleWorkspaceAccount" in userinfo and userinfo["googleWorkspaceAccount"] is not None:
        workspace_user = (
            get_google_workspace_client().get(userKey=userinfo["googleWorkspaceAccount"]).execute()
        )

        session["user_state"] = "provisioned"
        session["email_address"] = workspace_user["primaryEmail"]

        invite_user_to_hubspot.delay(workspace_user["id"])

        return redirect(url_for("index"))

    session["first_name"] = userinfo["given_name"] if "given_name" in userinfo else ""
    session["last_name"] = userinfo["family_name"] if "family_name" in userinfo else ""
    session["email_address"] = (
        session["first_name"] + "." + session["last_name"] + "@robojackets.org"
    ).lower()

    if "roles" in userinfo and "eligible" in userinfo["roles"]:
        session["user_state"] = "eligible"
    else:
        session["user_state"] = "ineligible"

    apiary_user_response = get(
        url=app.config["APIARY_URL"] + "/api/v1/users/" + userinfo["preferred_username"],
        headers={
            "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
            "Accept": "application/json",
        },
        params={"include": "roles,teams"},
        timeout=(5, 5),
    )

    if apiary_user_response.status_code == 200:
        apiary_user = apiary_user_response.json()["user"]

        role_check = False

        if "roles" in apiary_user and apiary_user["roles"] is not None:
            for role in apiary_user["roles"]:
                if role["name"] != "member" and role["name"] != "non-member":
                    role_check = True

        if (
            apiary_user["is_active"]
            and apiary_user["is_access_active"]
            and apiary_user["signed_latest_agreement"]
            and len(apiary_user["teams"]) > 0
            and role_check
        ):
            session["user_state"] = "eligible"

    elif apiary_user_response.status_code == 404:
        session["user_state"] = "ineligible"

    else:
        apiary_user_response.raise_for_status()

    if session["user_state"] == "ineligible":
        notify_slack_ineligible.delay(userinfo["sub"])

    return redirect(url_for("index"))


@app.post("/check-availability")
def check_availability() -> Any:
    """
    Check if a given email address is available for use
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    if session["user_state"] != "eligible":
        raise Unauthorized("Not eligible")

    set_user(
        {
            "id": session["sub"],
            "ip_address": request.remote_addr,
        }
    )

    if "emailAddress" not in request.json:  # type: ignore
        raise BadRequest("Missing email address")

    requested_email_address = request.json["emailAddress"].lower()  # type: ignore

    search_keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        params={
            "q": "googleWorkspaceAccount:" + requested_email_address,
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) > 0:
        return {"available": False}

    try:
        get_google_workspace_client().get(userKey=requested_email_address).execute()

        return {"available": False}
    except HttpError as e:
        if e.status_code != 404:
            raise e

    return {"available": True}


@app.post("/")
def submit() -> Any:
    """
    Create the Google Workspace account
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    if session["user_state"] != "eligible":
        raise Unauthorized("Not eligible")

    set_user(
        {
            "id": session["sub"],
            "ip_address": request.remote_addr,
        }
    )

    new_workspace_user = (
        get_google_workspace_client()
        .insert(
            body={
                "name": {
                    "givenName": request.form["first_name"].strip(),
                    "familyName": request.form["last_name"].strip(),
                },
                "primaryEmail": request.form["email_address"].strip(),
                "password": uuid4().hex,
            },
            resolveConflictAccount=True,
        )
        .execute()
    )

    get_keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    new_user = get_keycloak_user_response.json()
    if "id" in new_user:
        del new_user["id"]

    if "username" in new_user:
        del new_user["username"]

    if "attributes" not in new_user:
        new_user["attributes"] = {"googleWorkspaceAccount": [new_workspace_user["primaryEmail"]]}
    else:
        new_user["attributes"]["googleWorkspaceAccount"] = [new_workspace_user["primaryEmail"]]

    update_keycloak_user_response = put(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        json=new_user,
        headers={
            "Authorization": "Bearer " + get_keycloak_access_token(),
        },
        timeout=(5, 5),
    )
    update_keycloak_user_response.raise_for_status()

    remove_eligible_role.delay(session["sub"])
    import_user_to_org_chart.delay(new_workspace_user["id"])
    notify_slack_account_created.delay(session["sub"])

    # gmail routing doesn't work immediately when a new account is created,
    # so we wait 60 seconds before sending the hubspot invitation and hope that's long enough
    invite_user_to_hubspot.apply_async((new_workspace_user["id"],), countdown=60)

    return redirect(
        "https://www.google.com/a/robojackets.org/ServiceLogin?continue=https://workspace.google.com/dashboard"  # noqa
    )


@app.post("/slack")
def handle_slack_event() -> Dict[str, str]:
    """
    Handle an interaction event from Slack

    https://docs.slack.dev/interactivity/handling-user-interaction#payloads
    """
    verifier = SignatureVerifier(app.config["SLACK_SIGNING_SECRET"])

    if not verifier.is_valid_request(request.get_data(), request.headers):  # type: ignore
        raise Unauthorized("signature verification failed")

    payload = loads(request.form.get("payload"))  # type: ignore

    if payload["actions"][0]["action_id"] == "view_in_apiary":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "view_in_workspace":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "view_in_keycloak":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "grant_eligibility_in_keycloak":
        add_eligible_role_response = post(
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + str(UUID(payload["actions"][0]["value"]))
            + "/role-mappings/clients/"
            + app.config["KEYCLOAK_CLIENT_UUID"],
            headers={
                "Authorization": "Bearer " + get_keycloak_access_token(),
            },
            timeout=(5, 5),
            json=[{"id": app.config["KEYCLOAK_CLIENT_ROLE_ELIGIBLE"], "name": "eligible"}],
        )
        add_eligible_role_response.raise_for_status()

        slack = WebhookClient(url=payload["response_url"])
        slack.send(
            text=payload["message"]["text"],
            blocks=[
                payload["message"]["blocks"][0],
                ActionsBlock(
                    elements=[
                        payload["message"]["blocks"][1]["elements"][0],
                        payload["message"]["blocks"][1]["elements"][1],
                    ]
                ),
                SectionBlock(
                    text=":white_check_mark: *<@"
                    + payload["user"]["id"]
                    + "> granted eligibility in Keycloak*"
                ),
            ],
            replace_original=True,
        )

        return {"status": "ok"}

    raise BadRequest("unrecognized action_id")


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}


@app.get("/clear-cache")
def clear_cache() -> Dict[str, str]:
    """
    Clears the cache
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    if session["user_state"] != "provisioned":
        raise Unauthorized("Not provisioned")

    cache.clear()
    return {"status": "ok"}
