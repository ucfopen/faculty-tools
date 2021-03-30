import os
# Title of the tool. Appears in the <title> element, headers, and configuration XML
TOOL_TITLE = os.environ.get("TOOL_TITLE", "Faculty Tools")

# Which theme directory to use. Leave blank for default.
THEME_DIR = os.environ.get("THEME_DIR", "")

# Canvas instance URL. ex: https://example.instructure.com/
BASE_URL = os.environ.get("API_URL")
API_URL = BASE_URL + "api/v1/"

# Secret key to sign Flask sessions with. KEEP THIS SECRET!
secret_key = os.environ.get("SECRET_KEY")

# LTI consumer key and shared secret
CONSUMER_KEY = os.environ.get("LTI_KEY")
SHARED_SECRET = os.environ.get("LTI_SECRET")

# Configuration for pylti library. Uses the above key and secret
PYLTI_CONFIG = {
    "consumers": {
        CONSUMER_KEY: {
            "secret": SHARED_SECRET
        }
    },
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
oauth2_uri = os.environ.get("OAUTH2_URI")  # ex. 'https://localhost:5000/oauthlogin'
# The Client_ID Instructure gave you
oauth2_id = os.environ.get("OAUTH2_ID")
# The Secret Instructure gave you
oauth2_key = os.environ.get("OAUTH2_KEY")

# Logging configuration
LOG_MAX_BYTES = 1024 * 1024 * 5  # 5 MB
LOG_BACKUP_COUNT = 2
ERROR_LOG = "logs/faculty-tools.log"

whitelist = "whitelist.json"

# Google Analytics Tracking ID (optional)
GOOGLE_ANALYTICS = os.environ.get("GOOGLE_ANALYTICS", "GA-")


configClass = os.environ.get("CONFIG", "config.DevelopmentConfig")