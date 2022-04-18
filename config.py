import os


class Config(object):
    # make the warning shut up until Flask-SQLAlchemy v3 comes out
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # LTI consumer key and shared secret
    CONSUMER_KEY = os.environ.get("LTI_KEY")
    SHARED_SECRET = os.environ.get("LTI_SECRET")

    # Configuration for pylti library. Uses the above key and secret
    PYLTI_CONFIG = {
        "consumers": {CONSUMER_KEY: {"secret": SHARED_SECRET}},
        # Custom configurable roles
        "roles": {
            "staff": [
                "urn:lti:instrole:ims/lis/Administrator",
                "Instructor",
                "ContentDeveloper",
                "urn:lti:role:ims/lis/TeachingAssistant",
            ]
        },
    }

    SESSION_COOKIE_NAME = "ft_session"

    # Chrome 80 SameSite=None; Secure fix
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "None"

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")


class BaseConfig(object):
    DEBUG = False
    TESTING = False

    # make the warning shut up until Flask-SQLAlchemy v3 comes out
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    SESSION_COOKIE_NAME = "ft_session"

    # Chrome 80 SameSite=None; Secure fix
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "None"

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")

    # Title of the tool. Appears in the <title> element, headers, and configuration XML
    TOOL_TITLE = os.environ.get("TOOL_TITLE", "Faculty Tools")

    # Which theme directory to use. Leave blank for default.
    THEME_DIR = os.environ.get("THEME_DIR", "")

    # Canvas instance URL. ex: https://example.instructure.com/
    BASE_URL = os.environ.get("BASE_CANVAS_SERVER_URL", "https://example.com")
    API_URL = BASE_URL + "api/v1/"

    # Secret key to sign Flask sessions with. KEEP THIS SECRET!
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # LTI consumer key and shared secret
    CONSUMER_KEY = os.environ.get("LTI_KEY")
    SHARED_SECRET = os.environ.get("LTI_SECRET")

    # Configuration for pylti library. Uses the above key and secret
    PYLTI_CONFIG = {
        "consumers": {CONSUMER_KEY: {"secret": SHARED_SECRET}},
        # Custom configurable roles
        "roles": {
            "staff": [
                "urn:lti:instrole:ims/lis/Administrator",
                "Instructor",
                "ContentDeveloper",
                "urn:lti:role:ims/lis/TeachingAssistant",
            ]
        },
    }

    # The "Oauth2 Redirect URI" that you provided to Instructure.
    OAUTH2_URI = os.environ.get("OAUTH2_URI")  # ex. 'https://localhost:5000/oauthlogin'
    # The Client_ID Instructure gave you
    OAUTH2_ID = os.environ.get("OAUTH2_ID")
    # The Secret Instructure gave you
    OAUTH2_KEY = os.environ.get("OAUTH2_KEY")

    WHITELIST = os.environ.get("WHITELIST_JSON")

    # Google Analytics Tracking ID (optional)
    GOOGLE_ANALYTICS = os.environ.get("GOOGLE_ANALYTICS", "GA-")


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = True

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")
