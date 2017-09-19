# UCF_ID = '***REMOVED***'
UCF_ID = '1'


BASE_URL = 'http://192.168.99.100:3000/'
API_URL = 'http://192.168.99.100:3000/api/v1/'

# consumer key and secret

PYLTI_CONFIG = {
    'consumers': {
        "key": {
            "secret": "secret"
        }
    }
}

secret_key = '6282f598637b50f5a2d70c70bee6a0cf7572193fd861f990e08ef8d530136169'

# $oauth2_id: The Client_ID Instructure gives you
# $oauth2_key: The Secret Instructure gives you
# $oauth2_uri: The "Oauth2 Redirect URI" you provided instructure.

oauth2_id = "10000000000035"
oauth2_key = "s7G4hd0L5zXdVzwUAEZg7GoXxM6L4ZiCAGWpSfyUEPJu4IFNO0vW0uevabyZMA6N"
oauth2_uri = "http://127.0.0.1:5000/oauthlogin"

LOG_MAX_BYTES = 10000
LOG_BACKUP_COUNT = 1
ERROR_LOG = "error.log"


def select_db(x):
    return {
        'DevelopmentConfig': 'sqlite:///test.db',
        'Config': 'sqlite:///test.db',
        'BaseConfig': 'sqlite:///test.db',
        'TestingConfig': 'sqlite:///test.db'
    }.get(x, 'sqlite:///test2.db')


configClass = 'config.DevelopmentConfig'

whitelist = "whitelist.json"

GOOGLE_ANALYTICS = ''
