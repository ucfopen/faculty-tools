import settings


class Config(object):
    # make the warning shut up until Flask-SQLAlchemy v3 comes out
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = settings.select_db("Config")

    PYLTI_CONFIG = settings.PYLTI_CONFIG

    SESSION_COOKIE_NAME = "ft_session"

    # Chrome 80 SameSite=None; Secure fix
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "None"


class BaseConfig(object):
    DEBUG = False
    TESTING = False

    # make the warning shut up until Flask-SQLAlchemy v3 comes out
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = settings.select_db("BaseConfig")

    PYLTI_CONFIG = settings.PYLTI_CONFIG

    SESSION_COOKIE_NAME = "ft_session"

    # Chrome 80 SameSite=None; Secure fix
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "None"


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = True

    SQLALCHEMY_DATABASE_URI = settings.select_db("DevelopmentConfig")


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True

    SQLALCHEMY_DATABASE_URI = settings.select_db("TestingConfig")
