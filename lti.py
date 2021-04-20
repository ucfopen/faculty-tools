from logging import Formatter, INFO
from logging.handlers import RotatingFileHandler
import json
import os
import time

from canvasapi.exceptions import CanvasException
from flask import (
    Flask,
    render_template,
    session,
    request,
    redirect,
    url_for,
    Response,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import jinja2
from pylti.flask import lti
import requests
from requests.exceptions import HTTPError

from utils import filter_tool_list, slugify
import settings

app = Flask(__name__)
app.config.from_object(settings.configClass)
app.secret_key = settings.secret_key
db = SQLAlchemy(app)


def select_theme_dirs():
    """
    Load theme templates, if applicable
    """
    if settings.THEME_DIR:
        return ["themes/" + settings.THEME_DIR + "/templates", "templates"]
    else:
        return ["templates"]


theme_dirs = select_theme_dirs()
app.jinja_loader = jinja2.ChoiceLoader([jinja2.FileSystemLoader(theme_dirs)])

# Logging
handler = RotatingFileHandler(
    settings.ERROR_LOG,
    maxBytes=settings.LOG_MAX_BYTES,
    backupCount=settings.LOG_BACKUP_COUNT,
)
handler.setLevel(INFO)
handler.setFormatter(
    Formatter(
        "%(asctime)s %(levelname)s: %(message)s "
        "[in %(pathname)s: %(lineno)d of %(funcName)s]"
    )
)
app.logger.addHandler(handler)


# DB Model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True)
    refresh_key = db.Column(db.String(255))
    expires_in = db.Column(db.BigInteger)

    def __init__(self, user_id, refresh_key, expires_in):
        self.user_id = user_id
        self.refresh_key = refresh_key
        self.expires_in = expires_in

    def __repr__(self):
        return "<User %r>" % self.user_id


# Utility Functions
@app.context_processor
def ga_utility_processor():
    def google_analytics():
        return settings.GOOGLE_ANALYTICS

    return dict(google_analytics=google_analytics())


@app.context_processor
def title_utility_processor():
    def title():
        return settings.TOOL_TITLE

    return dict(title=title())


@app.context_processor
def theme_static_files_processor():
    def theme_static_files(folder):
        if not settings.THEME_DIR:
            return list()

        try:
            all_files = os.listdir(
                "themes/{theme_dir}/static/{folder}".format(
                    theme_dir=settings.THEME_DIR, folder=folder
                )
            )

            css_files = list()
            for file in all_files:
                if file.endswith(".{folder}".format(folder=folder)):
                    css_files.append(file)
        except OSError:
            return list()

        return css_files

    return {
        "theme_static_css": theme_static_files("css"),
        "theme_static_js": theme_static_files("js"),
    }


@app.template_filter("slugify")
def _slugify(string):
    if not string:
        return ""
    return slugify(string)


def return_error(msg):
    return render_template("error.html", msg=msg)


# for the pylti decorator
def error(exception=None):
    app.logger.error("PyLTI error: {}".format(exception))
    return return_error(
        (
            "Authentication error, please refresh and try again. If this error "
            "persists, please contact support."
        )
    )


@app.route("/themes/static/<path:filename>")
def theme_static(filename):  # pragma: nocover
    static_dir = "themes/{theme_dir}/static".format(theme_dir=settings.THEME_DIR)
    return send_from_directory(static_dir, filename)


# Web Views / Routes
@app.route("/")
@lti(error=error, role="staff", app=app)
def index(lti=lti):
    """
    Main entry point to web application, get all whitelisted LTIs and send the data to the template
    """

    if "api_key" not in session:
        app.logger.error("api_key not set")
        return return_error(
            (
                "Authentication error: missing API key. Please refresh and try again."
                "If this error persists, please contact support."
            )
        )

    # Test API key to see if they need to reauthenticate
    auth_header = {"Authorization": "Bearer " + session["api_key"]}
    r = requests.get(settings.API_URL + "users/self", headers=auth_header)
    if "WWW-Authenticate" in r.headers:
        # reroll oauth
        app.logger.info(
            (
                "WWW-Authenticate found in headers, or status code was 401. "
                "Re-rolling oauth.\n {0} \n {1} \n {2}"
            ).format(r.status_code, r.headers, r.url)
        )

        return redirect(
            settings.BASE_URL
            + "login/oauth2/auth?client_id="
            + settings.oauth2_id
            + "&response_type=code&redirect_uri="
            + settings.oauth2_uri
        )

    if "WWW-Authenticate" not in r.headers and r.status_code == 401:
        # not authorized
        app.logger.warning("Not an Admin. Not allowed.")
        return return_error(
            (
                "You are not enrolled in this course as a Teacher or Designer. "
                "If this error persists, please contact support."
            )
        )

    if r.status_code == 404:
        # something is wrong with the key! It can't get user out of the API key
        app.logger.error(
            (
                "404 in checking the user's api key. Request info:\n"
                "User ID: {0} Course: {1} \n {2} \n Request headers: {3} \n {4}"
            ).format(
                session["canvas_user_id"],
                session["course_id"],
                r.url,
                r.headers,
                r.json(),
            )
        )
        return redirect(
            settings.BASE_URL
            + "login/oauth2/auth?client_id="
            + settings.oauth2_id
            + "&response_type=code&redirect_uri="
            + settings.oauth2_uri
        )

    r = requests.get(
        settings.API_URL
        + "courses/{0}/external_tools?include_parents=true&per_page=100".format(
            session["course_id"]
        ),
        headers=auth_header,
    )

    try:
        tools_by_category, cagetory_order = filter_tool_list(
            session["course_id"], session["api_key"]
        )
    except CanvasException:
        app.logger.exception("Couldn't connect to Canvas")
        return return_error(
            (
                "Couldn't connect to Canvas, please refresh and try again. "
                "If this error persists please contact support."
            )
        )
    except (ValueError, IOError):
        msg = "There is something wrong with the whitelist.json file"
        app.logger.exception(msg)
        return return_error(msg)

    return render_template(
        "main_template.html",
        tools_by_category=tools_by_category,
        category_order=cagetory_order,
        course=session["course_id"],
    )


@app.route("/status", methods=["GET"])
def status():
    """
    Runs smoke tests and reports status
    """

    status = {
        "tool": "Faculty Tools",
        "checks": {"index": False, "xml": False, "db": False, "dev_key": False},
        "url": url_for("index", _external=True),
        "xml_url": url_for("xml", _external=True),
        "base_url": settings.BASE_URL,
        "debug": app.debug,
    }

    # Check index
    try:
        response = requests.get(url_for("index", _external=True), verify=False)
        index_check = (
            response.status_code == 200 and settings.TOOL_TITLE in response.text
        )
        status["checks"]["index"] = index_check
    except Exception:
        app.logger.exception("Index check failed.")

    # Check xml
    try:
        response = requests.get(url_for("xml", _external=True), verify=False)
        status["checks"]["xml"] = "application/xml" in response.headers.get(
            "Content-Type"
        )
    except Exception:
        app.logger.exception("XML check failed.")

    # Check DB connection
    try:
        db.session.query(text("1")).all()
        status["checks"]["db"] = True
    except Exception:
        app.logger.exception("DB connection failed.")

    # Check dev key?
    try:
        response = requests.get(
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}".format(
                settings.BASE_URL, settings.oauth2_id, settings.oauth2_uri
            )
        )
        status["checks"]["dev_key"] = response.status_code == 200
    except Exception:
        app.logger.exception("Dev Key check failed.")

    # Overall health check - if all checks are True
    status["healthy"] = all(v is True for k, v in list(status["checks"].items()))
    return Response(json.dumps(status), mimetype="application/json")


@app.route("/xml/", methods=["POST", "GET"])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    return Response(
        render_template("test.xml", url=request.url_root), mimetype="application/xml"
    )


# OAuth login
# Redirect URI
@app.route("/oauthlogin", methods=["POST", "GET"])
@lti(error=error, request="session", role="staff", app=app)
def oauth_login(lti=lti):

    code = request.args.get("code")

    if code is None:
        app.logger.warning("No `code` response from Canvas. User probaly hit 'Cancel'.")
        return return_error(
            (
                "Authentication error, please refresh and try again. If this error "
                "persists, please contact support."
            )
        )

    payload = {
        "grant_type": "authorization_code",
        "client_id": settings.oauth2_id,
        "redirect_uri": settings.oauth2_uri,
        "client_secret": settings.oauth2_key,
        "code": code,
    }
    r = requests.post(settings.BASE_URL + "login/oauth2/token", data=payload)

    try:
        r.raise_for_status()
    except HTTPError:
        app.logger.exception("Error status from oauth, authentication error")

        return return_error(
            (
                "Authentication error, please refresh and try again. If this error "
                "persists, please contact support."
            )
        )

    if "access_token" in r.json():
        session["api_key"] = r.json()["access_token"]

        if "refresh_token" in r.json():
            session["refresh_token"] = r.json()["refresh_token"]

        if "expires_in" in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = int(time.time())
            expires_in = current_time + r.json()["expires_in"]
            session["expires_in"] = expires_in

            # check if user is in the db
            user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()
            if user is not None:
                try:
                    # update the current user's expiration time in db
                    user.refresh_key = session["refresh_token"]
                    user.expires_in = session["expires_in"]
                    db.session.add(user)
                    db.session.commit()
                except Exception:
                    app.logger.exception(
                        "Error in updating user's expiration time in the db:\n {}".format(
                            session
                        )
                    )
                    return return_error(
                        "Authentication error, please refresh and try again. "
                        "If this error persists, please contact support."
                    )

                return redirect(url_for("index"))
            else:
                try:
                    # add new user to db
                    new_user = Users(
                        session["canvas_user_id"],
                        session["refresh_token"],
                        session["expires_in"],
                    )
                    db.session.add(new_user)
                    db.session.commit()
                except Exception:
                    # Error in adding user to the DB
                    app.logger.exception(
                        "Error in adding user to db: \n {}".format(session)
                    )
                    return return_error(
                        (
                            "Authentication error, please refresh and try again. "
                            "If this error persists, please contact support."
                        )
                    )

                return redirect(url_for("index"))

    app.logger.warning(
        (
            "Error with checking access_token in r.json() block\n"
            "User: {0} Course: {1} \n {2} \n Request headers: {3} \n r.json(): {4}"
        ).format(
            session["canvas_user_id"], session["course_id"], r.url, r.headers, r.json()
        )
    )
    return return_error(
        (
            "Authentication error, please refresh and try again. If this error "
            "persists, please contact support."
        )
    )


def refresh_access_token(user):
    """
    Use a user's refresh token to get a new access token.

    :rtype: dict
    :returns: Dictionary with keys 'access_token' and 'expiration_date'.
        Values will be `None` if refresh fails.
    """
    refresh_token = user.refresh_key

    payload = {
        "grant_type": "refresh_token",
        "client_id": settings.oauth2_id,
        "redirect_uri": settings.oauth2_uri,
        "client_secret": settings.oauth2_key,
        "refresh_token": refresh_token,
    }
    response = requests.post(settings.BASE_URL + "login/oauth2/token", data=payload)

    try:
        response.raise_for_status()
    except HTTPError:
        app.logger.exception("Failed refresh. Probably bad refresh token.")
        return {"access_token": None, "expiration_date": None}

    try:
        response_json = response.json()
    except ValueError:
        app.logger.exception(
            "Unable to load JSON response of refresh. Possibly bad refresh token."
        )
        return {"access_token": None, "expiration_date": None}

    if "access_token" not in response_json:
        app.logger.warning(
            (
                "Access token not in json. Bad api key or refresh token.\n"
                "URL: {}\n"
                "Status Code: {}\n"
                "Payload: {}\n"
                "Session: {}"
            ).format(response.url, response.status_code, payload, session)
        )
        return {"access_token": None, "expiration_date": None}

    api_key = response_json["access_token"]
    app.logger.info("New access token created\n User: {0}".format(user.user_id))

    if "expires_in" not in response_json:
        app.logger.warning(
            (
                "expires_in not in json. Bad api key or refresh token.\n"
                "URL: {}\n"
                "Status Code: {}\n"
                "Payload: {}\n"
                "Session: {}"
            ).format(response.url, response.status_code, payload, session)
        )
        return {"access_token": None, "expiration_date": None}

    current_time = int(time.time())
    new_expiration_date = current_time + response_json["expires_in"]

    try:
        # Update expiration date in db
        user.expires_in = new_expiration_date
        db.session.commit()
    except Exception:
        readable_expires_in = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(user.expires_in)
        )
        readable_new_expiration = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(new_expiration_date)
        )
        app.logger.error(
            (
                "Error in updating user's expiration time in the db:\n"
                "session: {}\n"
                "DB expires_in: {}\n"
                "new_expiration_date: {}"
            ).format(session, readable_expires_in, readable_new_expiration)
        )
        return {"access_token": None, "expiration_date": None}

    return {"access_token": api_key, "expiration_date": new_expiration_date}


# Checking the user in the db
@app.route("/auth", methods=["POST", "GET"])
@lti(error=error, request="initial", role="staff", app=app)
def auth(lti=lti):
    session["course_id"] = request.form.get("custom_canvas_course_id")
    session["canvas_user_id"] = request.form.get("custom_canvas_user_id")

    # Try to grab the user
    user = Users.query.filter_by(user_id=int(session["canvas_user_id"])).first()

    if not user:
        # not in db, go go oauth!!
        app.logger.info(
            "Person doesn't have an entry in db, redirecting to oauth: {0}".format(
                session["canvas_user_id"]
            )
        )
        return redirect(
            settings.BASE_URL
            + "login/oauth2/auth?client_id="
            + settings.oauth2_id
            + "&response_type=code&redirect_uri="
            + settings.oauth2_uri
        )

    # Get the expiration date
    expiration_date = user.expires_in

    # If expired or no api_key
    if int(time.time()) > expiration_date or "api_key" not in session:
        readable_time = time.strftime(
            "%a, %d %b %Y %H:%M:%S", time.localtime(user.expires_in)
        )
        app.logger.info(
            (
                "Expired refresh token or api_key not in session\n User: {0} \n "
                "Expiration date in db: {1} Readable expires_in: {2}"
            ).format(user.user_id, user.expires_in, readable_time)
        )

        refresh = refresh_access_token(user)

        if refresh["access_token"] and refresh["expiration_date"]:
            session["api_key"] = refresh["access_token"]
            session["expires_in"] = refresh["expiration_date"]
            return redirect(url_for("index"))
        else:
            # Refresh didn't work. Reauthenticate.
            app.logger.info("Reauthenticating:\nSession: {}".format(session))
            return redirect(
                settings.BASE_URL
                + "login/oauth2/auth?client_id="
                + settings.oauth2_id
                + "&response_type=code&redirect_uri="
                + settings.oauth2_uri
            )
    else:
        # API key that shouldn't be expired. Test it.
        auth_header = {"Authorization": "Bearer " + session["api_key"]}
        r = requests.get(
            settings.API_URL + "users/%s/profile" % (session["canvas_user_id"]),
            headers=auth_header,
        )
        # check for WWW-Authenticate
        # https://canvas.instructure.com/doc/api/file.oauth.html
        if "WWW-Authenticate" not in r.headers and r.status_code != 401:
            return redirect(url_for("index"))
        else:
            # Key is bad. First try to get new one using refresh
            new_token = refresh_access_token(user)["access_token"]

            if new_token:
                session["api_key"] = new_token
                return redirect(url_for("index"))
            else:
                # Refresh didn't work. Reauthenticate.
                app.logger.info("Reauthenticating\nSession: {}".format(session))
                return redirect(
                    settings.BASE_URL
                    + "login/oauth2/auth?client_id="
                    + settings.oauth2_id
                    + "&response_type=code&redirect_uri="
                    + settings.oauth2_uri
                )


@app.route("/get_sessionless_url/<lti_id>/<is_course_nav>")
@lti(error=error, role="staff", app=app)
def get_sessionless_url(lti_id, is_course_nav, lti=lti):
    sessionless_launch_url = None

    if is_course_nav == "True":
        auth_header = {"Authorization": "Bearer " + session["api_key"]}
        # get sessionless launch url for things that come from course nav
        url = (
            "{0}courses/{1}/external_tools/sessionless_launch?id={2}"
            "&launch_type=course_navigation"
        )
        r = requests.get(
            url.format(settings.API_URL, session["course_id"], lti_id),
            headers=auth_header,
        )
        if r.status_code >= 400:
            app.logger.error(
                (
                    "Bad response while getting a sessionless "
                    "launch url:\n {0} {1}\n LTI: {2} \n"
                ).format(r.status_code, r.url, lti_id)
            )
            return return_error(
                (
                    "Error in a response from Canvas, please "
                    "refresh and try again. If this error persists, "
                    "please contact support."
                )
            )
        else:
            sessionless_launch_url = r.json()["url"]

    if sessionless_launch_url is None:
        auth_header = {"Authorization": "Bearer " + session["api_key"]}
        # get sessionless launch url
        r = requests.get(
            settings.API_URL
            + "courses/{0}/external_tools/sessionless_launch?id={1}".format(
                session["course_id"], lti_id
            ),
            headers=auth_header,
        )
        if r.status_code >= 400:
            app.logger.error(
                (
                    "Bad response while getting a sessionless "
                    "launch url:\n {0} {1}\n LTI: {2} \n"
                ).format(r.status_code, r.url, lti_id)
            )
            return return_error(
                (
                    "Error in a response from Canvas, please "
                    "refresh and try again. If this error persists, "
                    "please contact support."
                )
            )
        else:
            sessionless_launch_url = r.json()["url"]

    return sessionless_launch_url
