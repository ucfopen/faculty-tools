from json.decoder import JSONDecodeError
import logging
import unittest
from urllib.parse import urlencode

import canvasapi
import oauthlib.oauth1
import flask
from flask import Flask, url_for
import flask_testing
import requests_mock
from pylti.common import LTI_SESSION_KEY
import time

from mock import patch, mock_open
import lti
import utils


@requests_mock.Mocker()
class LTITests(flask_testing.TestCase):
    def create_app(self):
        app = lti.app
        app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False
        app.config["API_URL"] = "https://example.edu/api/v1/"
        app.config["API_KEY"] = "p@$$w0rd"
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"
        app.config["SECRET_KEY"] = "S3cr3tK3y"
        app.config["SESSION_COOKIE_DOMAIN"] = None

        return app

    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        app = lti.app
        app.config["BASE_URL"] = "https://example.edu/"
        app.config["OAUTH2_ID"] = "10000000000001"
        app.config["OAUTH2_URI"] = "oauthlogin"
        app.config["GOOGLE_ANALYTICS"] = "123abc"
        app.config["THEME_DIR"] = "test_theme"

    def setUp(self):
        with self.app.test_request_context():
            lti.db.create_all()

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)

    def tearDown(self):
        lti.db.session.remove()
        lti.db.drop_all()

    @staticmethod
    def generate_launch_request(
        url,
        body=None,
        http_method="GET",
        base_url="http://localhost",
        roles="Instructor",
        headers=None,
        params=None,
    ):
        if params is None:
            params = {}

        if roles is not None:
            params["roles"] = roles

        urlparams = urlencode(params)

        client = oauthlib.oauth1.Client(
            "key",
            client_secret="secret",
            signature_method=oauthlib.oauth1.SIGNATURE_HMAC,
            signature_type=oauthlib.oauth1.SIGNATURE_TYPE_QUERY,
        )
        signature = client.sign(
            "{}{}?{}".format(base_url, url, urlparams),
            body=body,
            http_method=http_method,
            headers=headers,
        )
        signed_url = signature[0]
        new_url = signed_url[len(base_url) :]
        return new_url

    def test_select_theme_dirs(self, m):
        theme_dirs = lti.select_theme_dirs()

        self.assertIsInstance(theme_dirs, list)
        self.assertEqual(len(theme_dirs), 2)
        self.assertEqual(theme_dirs[0], "themes/test_theme/templates")
        self.assertEqual(theme_dirs[1], "templates")

    # @patch('self.app.config["BASE_URL"]', "")
    def test_select_theme_dirs_no_theme(self, m):
        self.app.config["BASE_URL"] = ""
        self.app.config["THEME_DIR"] = ""
        theme_dirs = lti.select_theme_dirs()

        self.assertIsInstance(theme_dirs, list)
        self.assertEqual(len(theme_dirs), 1)
        self.assertIn("templates", theme_dirs)

    def test__slugify(self, m):
        self.assertEqual(lti._slugify("test"), "test")
        self.assertEqual(lti._slugify("CAPSTOLOWER"), "capstolower")
        self.assertEqual(lti._slugify("spaces to dashes"), "spaces-to-dashes")

    def test__slugify_empty(self, m):
        self.assertEqual(lti._slugify(""), "")
        self.assertEqual(lti._slugify(None), "")
        self.assertEqual(lti._slugify(dict()), "")
        self.assertEqual(lti._slugify(list()), "")

    @patch("os.listdir")
    def test_theme_static_files_processor(self, m, mocked_listdir):
        self.app.config["THEME_DIR"] = "test_theme"
        mocked_listdir.return_value = ["file1.css", "file2.js"]
        files = lti.theme_static_files_processor()

        self.assertIsInstance(files, dict)
        self.assertEqual(len(files), 2)
        self.assertIn("theme_static_css", files)
        self.assertIsInstance(files["theme_static_css"], list)
        self.assertEqual(len(files["theme_static_css"]), 1)
        self.assertEqual(files["theme_static_css"][0], "file1.css")
        self.assertIn("theme_static_js", files)
        self.assertIsInstance(files["theme_static_js"], list)
        self.assertEqual(len(files["theme_static_js"]), 1)
        self.assertEqual(files["theme_static_js"][0], "file2.js")

    @patch("os.listdir")
    def test_theme_static_files_processor_oserror(self, m, mocked_listdir):
        mocked_listdir.side_effect = OSError

        files = lti.theme_static_files_processor()

        self.assertIsInstance(files, dict)
        self.assertEqual(len(files), 2)
        self.assertIn("theme_static_css", files)
        self.assertIsInstance(files["theme_static_css"], list)
        self.assertEqual(len(files["theme_static_css"]), 0)
        self.assertIn("theme_static_js", files)
        self.assertIsInstance(files["theme_static_js"], list)
        self.assertEqual(len(files["theme_static_js"]), 0)

    # @patch('app.config["THEME_DIR"]', "")
    def test_theme_static_files_processor_no_theme(self, m):
        self.app.config["THEME_DIR"] = ""
        files = lti.theme_static_files_processor()

        self.assertIsInstance(files, dict)
        self.assertEqual(len(files), 2)
        self.assertIn("theme_static_css", files)
        self.assertIsInstance(files["theme_static_css"], list)
        self.assertEqual(len(files["theme_static_css"]), 0)
        self.assertIn("theme_static_js", files)
        self.assertIsInstance(files["theme_static_js"], list)
        self.assertEqual(len(files["theme_static_js"]), 0)

    # Users
    def test_Users_init(self, m):
        user_id = 1
        refresh_key = "S3cr3tK3y"
        expires_in = 1556635930

        user = lti.Users(user_id, refresh_key, expires_in)

        self.assertIsInstance(user, lti.Users)
        self.assertEqual(user.user_id, user_id)
        self.assertEqual(user.refresh_key, refresh_key)
        self.assertEqual(user.expires_in, expires_in)

    def test_Users_repr(self, m):
        user = lti.Users(1, "test", 123)
        user_str = user.__repr__()
        self.assertIsInstance(user_str, str)

    # ga_utility_processor
    def test_ga_utility_processor(self, m):
        ga = lti.ga_utility_processor()

        self.assertIsInstance(ga, dict)
        self.assertIn("google_analytics", ga)
        self.assertEqual(ga["google_analytics"], self.app.config["GOOGLE_ANALYTICS"])

    # title_utility_processor
    def test_title_utility_processor(self, m):
        title = lti.title_utility_processor()

        self.assertIsInstance(title, dict)
        self.assertIn("title", title)
        self.assertEqual(title["title"], self.app.config["TOOL_TITLE"])

    # return_error
    def test_return_error(self, m):
        message = "Oh no!"
        response = lti.return_error(message)
        self.assert_template_used("error.html")
        self.assertIn(message, response)

    # error
    def test_error(self, m):
        response = lti.error()
        self.assert_template_used("error.html")
        self.assertIn("Authentication error, please refresh and try again.", response)

    # def test_theme_static(self, m):
    #     with patch("flask.send_from_directory") as mocked:
    #         # patched.side_effect = Exception()
    #         mocked_return_value = "OH HELLO"
    #         response = self.client.get('themes/static/test')
    #         print(response)

    #     mocked.assert_called()

    # index
    def test_index_no_auth(self, m):
        response = self.client.get(url_for("index"))

        self.assert_200(response)
        self.assert_template_used("error.html")

        self.assertIn(
            b"Authentication error, please refresh and try again", response.data
        )

    def test_index_api_key_none(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"

        response = self.client.get(self.generate_launch_request(url_for("index")))

        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Authentication error: missing API key. Please refresh and try again.",
            response.data,
        )

    def test_index_api_key_expired(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"

        m.register_uri(
            "GET",
            "/api/v1/users/self",
            headers={"WWW-Authenticate": 'Bearer realm="canvas-lms"'},
            status_code=401,
        )

        response = self.client.get(self.generate_launch_request(url_for("index")))
        redirect_url = (
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}"
        )
        self.assert_redirects(
            response,
            redirect_url.format(
                self.app.config["BASE_URL"],
                self.app.config["OAUTH2_ID"],
                self.app.config["OAUTH2_URI"],
            ),
        )

    def test_index_api_key_invalid(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"

        m.register_uri("GET", "/api/v1/users/self", status_code=401)

        response = self.client.get(self.generate_launch_request(url_for("index")))
        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"You are not enrolled in this course as a Teacher or Designer.",
            response.data,
        )

    def test_index_api_key_404(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("GET", "/api/v1/users/self", json={}, status_code=404)

        response = self.client.get(self.generate_launch_request(url_for("index")))

        redirect_url = (
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}"
        )
        self.assert_redirects(
            response,
            redirect_url.format(
                self.app.config["BASE_URL"],
                self.app.config["OAUTH2_ID"],
                self.app.config["OAUTH2_URI"],
            ),
        )

    def test_index_no_canvas_conn(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("GET", "/api/v1/users/self", status_code=200)
        m.register_uri("GET", "/api/v1/courses/1", json={"id": 1}, status_code=200)
        m.register_uri(
            "GET", "/api/v1/courses/1/external_tools", json={}, status_code=404
        )

        response = self.client.get(self.generate_launch_request(url_for("index")))
        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Couldn&#39;t connect to Canvas, please refresh and try again",
            response.data,
        )

    @patch("lti.filter_tool_list")
    def test_index_whitelist_error(self, m, filter_tool_list):
        filter_tool_list.side_effect = IOError()

        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("GET", "/api/v1/users/self", status_code=200)
        m.register_uri("GET", "/api/v1/courses/1", json={"id": 1}, status_code=200)
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools",
            json=[
                {"id": 1, "name": "Tool #1", "description": "This is the first tool"}
            ],
            headers={
                "Link": '<{}api/v1/courses/1/external_tools?page=2>; rel="next"'.format(
                    self.app.config["BASE_URL"]
                )
            },
            status_code=200,
        )
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools?page=2",
            json=[
                {"id": 2, "name": "Tool #2", "description": "This is the second tool"}
            ],
            status_code=200,
        )

        response = self.client.get(self.generate_launch_request(url_for("index")))

        self.assert_template_used("error.html")
        self.assertIn(
            b"There is something wrong with the whitelist.json file", response.data
        )

    @patch("lti.filter_tool_list")
    def test_index_canvas_error(self, m, filter_tool_list):
        filter_tool_list.side_effect = canvasapi.exceptions.CanvasException(
            "Something went wrong"
        )

        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("GET", "/api/v1/users/self", status_code=200)
        m.register_uri("GET", "/api/v1/courses/1", json={"id": 1}, status_code=200)
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools",
            json=[
                {"id": 1, "name": "Tool #1", "description": "This is the first tool"}
            ],
            headers={
                "Link": '<{}api/v1/courses/1/external_tools?page=2>; rel="next"'.format(
                    self.app.config["BASE_URL"]
                )
            },
            status_code=200,
        )
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools?page=2",
            json=[
                {"id": 2, "name": "Tool #2", "description": "This is the second tool"}
            ],
            status_code=200,
        )

        response = self.client.get(self.generate_launch_request(url_for("index")))

        self.assert_template_used("error.html")
        self.assertIn(b"Couldn&#39;t connect to Canvas", response.data)

    def test_index(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["api_key"] = "p@$$w0rd"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("GET", "/api/v1/users/self", status_code=200)
        m.register_uri("GET", "/api/v1/courses/1", json={"id": 1}, status_code=200)
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools",
            json=[
                {"id": 1, "name": "Tool #1", "description": "This is the first tool"}
            ],
            headers={
                "Link": '<{}api/v1/courses/1/external_tools?page=2>; rel="next"'.format(
                    self.app.config["BASE_URL"]
                )
            },
            status_code=200,
        )
        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools?page=2",
            json=[
                {"id": 2, "name": "Tool #2", "description": "This is the second tool"}
            ],
            status_code=200,
        )

        response = self.client.get(self.generate_launch_request(url_for("index")))
        self.assert_200(response)
        self.assert_template_used("main_template.html")

    # status
    def test_status_healthy(self, m):
        self.app.config["BASE_URL"] = "https://example.edu/"

        m.register_uri(
            "GET",
            "http://localhost/",
            status_code=200,
            text=self.app.config["TOOL_TITLE"],
        )
        m.register_uri(
            "GET",
            "http://localhost/xml/",
            status_code=200,
            headers={"Content-Type": "application/xml"},
        )
        m.register_uri("GET", "https://example.edu/login/oauth2/auth", status_code=200)

        response = self.client.get(url_for("status"))

        self.assert_200(response)
        self.assertTrue(response.is_json)

        json_response = response.json

        self.assertIn("checks", json_response)
        self.assertIsInstance(json_response["checks"], dict)
        self.assertEqual(len(json_response["checks"]), 4)
        for check, is_ok in json_response["checks"].items():
            self.assertTrue(is_ok)
        self.assertIn("healthy", json_response)
        self.assertTrue(json_response["healthy"])

    def test_status_failures(self, m):
        m.register_uri("GET", "http://localhost/", exc=Exception)
        m.register_uri(
            "GET",
            "http://localhost/xml/",
            status_code=200,
            # header intentionally omitted
        )

        with patch("lti.db.session.query") as mock:
            mock.side_effect = Exception

            response = self.client.get(url_for("status"))

        self.assert_200(response)
        self.assertTrue(response.is_json)

        json_response = response.json

        self.assertIn("checks", json_response)
        self.assertIsInstance(json_response["checks"], dict)
        self.assertEqual(len(json_response["checks"]), 4)
        for check, is_ok in json_response["checks"].items():
            self.assertFalse(is_ok)
        self.assertIn("healthy", json_response)
        self.assertFalse(json_response["healthy"])

    # xml
    def test_xml(self, m):
        response = self.client.get(url_for("xml"))

        self.assert_200(response)
        self.assert_template_used("test.xml")
        self.assertEqual(response.mimetype, "application/xml")

    # oauth_login
    def test_oauth_login_cancelled(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"

        m.register_uri("POST", "/login/oauth2/token", status_code=500)

        response = self.client.get(
            self.generate_launch_request(
                url_for("oauth_login"), http_method="POST", params={"code": "test"}
            )
        )

        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Authentication error, please refresh and try again.", response.data
        )

    def test_oauth_login_no_access_token(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1

        m.register_uri("POST", "/login/oauth2/token", status_code=200, json={})

        response = self.client.get(
            self.generate_launch_request(
                url_for("oauth_login"), http_method="POST", params={"code": "test"}
            )
        )

        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Authentication error, please refresh and try again.", response.data
        )

    def test_oauth_login_new_user(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        with self.client as client:
            with client.session_transaction() as sess:
                sess[LTI_SESSION_KEY] = True
                sess["oauth_consumer_key"] = "key"
                sess["roles"] = "Instructor"
                sess["canvas_user_id"] = 1
                sess["course_id"] = 1

            # Confirm that user doesn't already exist
            user = lti.Users.query.filter_by(
                user_id=int(sess["canvas_user_id"])
            ).first()
            self.assertIsNone(user)

            response = client.get(
                self.generate_launch_request(
                    url_for("oauth_login"), http_method="POST", params={"code": "test"}
                )
            )

            self.assert_redirects(response, url_for("index"))

            # Check that user is created
            user = lti.Users.query.filter_by(
                user_id=int(sess["canvas_user_id"])
            ).first()
            self.assertIsInstance(user, lti.Users)
            self.assertEqual(user.user_id, sess["canvas_user_id"])
            self.assertEqual(user.refresh_key, refresh_token)
            # LessEqual due to varying timing
            self.assertLessEqual(user.expires_in, int(time.time()) + expires_in)

            self.assertIn("api_key", flask.session)
            self.assertEqual(flask.session["api_key"], access_token)
            self.assertIn("refresh_token", flask.session)
            self.assertEqual(flask.session["refresh_token"], refresh_token)
            self.assertIn("expires_in", flask.session)
            # LessEqual due to varying timing
            self.assertLessEqual(
                flask.session["expires_in"], int(time.time()) + expires_in
            )

    def test_oauth_login_new_user_db_error(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        with self.client as client:
            with client.session_transaction() as sess:
                sess[LTI_SESSION_KEY] = True
                sess["oauth_consumer_key"] = "key"
                sess["roles"] = "Instructor"
                sess["canvas_user_id"] = 1
                sess["course_id"] = 1

            with patch("lti.db.session.commit") as mock:
                mock.side_effect = Exception

                response = client.get(
                    self.generate_launch_request(
                        url_for("oauth_login"),
                        http_method="POST",
                        params={"code": "test"},
                    )
                )

        self.assert_template_used("error.html")
        self.assertIn(
            b"Authentication error, please refresh and try again.", response.data
        )

    def test_oauth_login_existing_user(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        with self.client as client:
            with client.session_transaction() as sess:
                sess[LTI_SESSION_KEY] = True
                sess["oauth_consumer_key"] = "key"
                sess["roles"] = "Instructor"
                sess["canvas_user_id"] = 1
                sess["course_id"] = 1

            # Simulate some time having passed
            old_expire = int(time.time()) + (expires_in / 2)

            # pre-create user
            user = lti.Users(1, refresh_token, old_expire)
            lti.db.session.add(user)
            lti.db.session.commit()

            # Confirm that user is already in DB
            user = lti.Users.query.filter_by(
                user_id=int(sess["canvas_user_id"])
            ).first()
            self.assertIsInstance(user, lti.Users)
            self.assertEqual(user.user_id, sess["canvas_user_id"])
            self.assertEqual(user.refresh_key, refresh_token)
            self.assertEqual(user.expires_in, old_expire)

            response = client.get(
                self.generate_launch_request(
                    url_for("oauth_login"), http_method="POST", params={"code": "test"}
                )
            )

            self.assert_redirects(response, url_for("index"))
            self.assertGreater(user.expires_in, old_expire)

    def test_oauth_login_existing_user_db_error(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        with self.client as client:
            with client.session_transaction() as sess:
                sess[LTI_SESSION_KEY] = True
                sess["oauth_consumer_key"] = "key"
                sess["roles"] = "Instructor"
                sess["canvas_user_id"] = 1
                sess["course_id"] = 1

            # Simulate some time having passed
            old_expire = int(time.time()) + (expires_in / 2)

            # pre-create user
            user = lti.Users(1, refresh_token, old_expire)
            lti.db.session.add(user)
            lti.db.session.commit()

            # Confirm that user is already in DB
            user = lti.Users.query.filter_by(
                user_id=int(sess["canvas_user_id"])
            ).first()
            self.assertIsInstance(user, lti.Users)
            self.assertEqual(user.user_id, sess["canvas_user_id"])
            self.assertEqual(user.refresh_key, refresh_token)
            self.assertEqual(user.expires_in, old_expire)

            with patch("lti.db.session.commit") as mock:
                mock.side_effect = Exception

                response = client.get(
                    self.generate_launch_request(
                        url_for("oauth_login"),
                        http_method="POST",
                        params={"code": "test"},
                    )
                )

            self.assert_200(response)
            self.assert_template_used("error.html")
            self.assertIn(
                b"Authentication error, please refresh and try again.", response.data
            )

    # refresh_access_token
    def test_refresh_access_token_no_access_token(self, m):
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri("POST", "/login/oauth2/token", status_code=200, json={})

        # Simulate some time having passed
        old_expire = int(time.time()) + (expires_in / 2)

        # pre-create user
        user = lti.Users(1, refresh_token, old_expire)
        lti.db.session.add(user)
        lti.db.session.commit()

        response = lti.refresh_access_token(user)

        self.assertIsInstance(response, dict)
        self.assertIn("access_token", response)
        self.assertIsNone(response["access_token"])
        self.assertIn("expiration_date", response)
        self.assertIsNone(response["expiration_date"])

    def test_refresh_access_token_no_exires_in(self, m):
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={"access_token": "@cc3$$_t0k3n"},
        )

        # Simulate some time having passed
        old_expire = int(time.time()) + (expires_in / 2)

        # pre-create user
        user = lti.Users(1, refresh_token, old_expire)
        lti.db.session.add(user)
        lti.db.session.commit()

        response = lti.refresh_access_token(user)

        self.assertIsInstance(response, dict)
        self.assertIn("access_token", response)
        self.assertIsNone(response["access_token"])
        self.assertIn("expiration_date", response)
        self.assertIsNone(response["expiration_date"])

    def test_refresh_access_token_db_error(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        # Simulate some time having passed
        old_expire = int(time.time()) + (expires_in / 2)

        # pre-create user
        user = lti.Users(1, refresh_token, old_expire)
        lti.db.session.add(user)
        lti.db.session.commit()

        with patch("lti.db.session.commit") as mock:
            mock.side_effect = Exception

            response = lti.refresh_access_token(user)

        self.assertIsInstance(response, dict)
        self.assertIn("access_token", response)
        self.assertIsNone(response["access_token"])
        self.assertIn("expiration_date", response)
        self.assertIsNone(response["expiration_date"])

    def test_refresh_access_token(self, m):
        access_token = "@cc3$$_t0k3n"
        refresh_token = "R3fr3$h_t0k3n"
        expires_in = 3600

        m.register_uri(
            "POST",
            "/login/oauth2/token",
            status_code=200,
            json={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
            },
        )

        # Simulate some time having passed
        old_expire = int(time.time()) + (expires_in / 2)

        # pre-create user
        user = lti.Users(1, refresh_token, old_expire)
        lti.db.session.add(user)
        lti.db.session.commit()

        response = lti.refresh_access_token(user)

        self.assertIsInstance(response, dict)
        self.assertIn("access_token", response)
        self.assertEqual(response["access_token"], access_token)
        self.assertIn("expiration_date", response)
        # LessEqual due to varying timing
        self.assertLessEqual(response["expiration_date"], int(time.time()) + expires_in)

        self.assertGreater(user.expires_in, old_expire)

    # auth
    def test_auth_no_user(self, m):
        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}

        # confirm that user doesn't exist
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsNone(user)

        response = self.client.post(
            self.generate_launch_request(
                url_for("auth"),
                body=payload,
                http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            data=payload,
        )

        redirect_url = (
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}"
        )
        self.assert_redirects(
            response,
            redirect_url.format(
                self.app.config["BASE_URL"],
                self.app.config["OAUTH2_ID"],
                self.app.config["OAUTH2_URI"],
            ),
        )

    @patch("lti.refresh_access_token")
    def test_auth_no_api_key_refresh_success(self, m, mock_refresh_access_token):
        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}
        refresh_token = "R3fr3$h_t0k3n"
        expiry_date = int(time.time()) + 1800

        new_access_token = "@cc3$$_t0k3n"
        new_expiry_date = int(time.time()) + 3600
        mock_refresh_access_token.return_value = {
            "access_token": new_access_token,
            "expiration_date": new_expiry_date,
        }

        # pre-create user
        user = lti.Users(1, refresh_token, expiry_date)
        lti.db.session.add(user)
        lti.db.session.commit()

        # Confirm that user is already in DB
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsInstance(user, lti.Users)

        with self.client as client:
            response = client.post(
                self.generate_launch_request(
                    url_for("auth"),
                    body=payload,
                    http_method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ),
                data=payload,
            )

            self.assertEqual(flask.session["api_key"], new_access_token)
            self.assertEqual(flask.session["expires_in"], new_expiry_date)

            self.assert_redirects(response, url_for("index"))

    @patch("lti.refresh_access_token")
    def test_auth_no_api_key_refresh_fail(self, m, mock_refresh_access_token):
        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}
        refresh_token = "R3fr3$h_t0k3n"
        expiry_date = int(time.time()) + 1800

        mock_refresh_access_token.return_value = {
            "access_token": None,
            "expiration_date": None,
        }

        # pre-create user
        user = lti.Users(1, refresh_token, expiry_date)
        lti.db.session.add(user)
        lti.db.session.commit()

        # Confirm that user is already in DB
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsInstance(user, lti.Users)

        response = self.client.post(
            self.generate_launch_request(
                url_for("auth"),
                body=payload,
                http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            data=payload,
        )

        redirect_url = (
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}"
        )
        self.assert_redirects(
            response,
            redirect_url.format(
                self.app.config["BASE_URL"],
                self.app.config["OAUTH2_ID"],
                self.app.config["OAUTH2_URI"],
            ),
        )

    @patch("lti.refresh_access_token")
    def test_auth_invalid_api_key_refresh_success(self, m, mock_refresh_access_token):
        with self.client.session_transaction() as sess:
            sess["api_key"] = "0ld_@cc3$$_t0k3n"

        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}
        refresh_token = "R3fr3$h_t0k3n"
        expiry_date = int(time.time()) + 1800

        new_access_token = "@cc3$$_t0k3n"
        new_expiry_date = int(time.time()) + 3600
        mock_refresh_access_token.return_value = {
            "access_token": new_access_token,
            "expiration_date": new_expiry_date,
        }

        m.register_uri(
            "GET",
            "/api/v1/users/1/profile",
            headers={"WWW-Authenticate": 'Bearer realm="canvas-lms"'},
            status_code=401,
        )

        # pre-create user
        user = lti.Users(1, refresh_token, expiry_date)
        lti.db.session.add(user)
        lti.db.session.commit()

        # Confirm that user is already in DB
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsInstance(user, lti.Users)

        response = self.client.post(
            self.generate_launch_request(
                url_for("auth"),
                body=payload,
                http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            data=payload,
        )

        self.assertRedirects(response, url_for("index"))

    @patch("lti.refresh_access_token")
    def test_auth_invalid_api_key_refresh_fail(self, m, mock_refresh_access_token):
        with self.client.session_transaction() as sess:
            sess["api_key"] = "0ld_@cc3$$_t0k3n"

        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}
        refresh_token = "R3fr3$h_t0k3n"
        expiry_date = int(time.time()) + 1800

        mock_refresh_access_token.return_value = {
            "access_token": None,
            "expiration_date": None,
        }

        m.register_uri(
            "GET",
            "/api/v1/users/1/profile",
            headers={"WWW-Authenticate": 'Bearer realm="canvas-lms"'},
            status_code=401,
        )

        # pre-create user
        user = lti.Users(1, refresh_token, expiry_date)
        lti.db.session.add(user)
        lti.db.session.commit()

        # Confirm that user is already in DB
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsInstance(user, lti.Users)

        response = self.client.post(
            self.generate_launch_request(
                url_for("auth"),
                body=payload,
                http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            data=payload,
        )

        redirect_url = (
            "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}"
        )
        self.assert_redirects(
            response,
            redirect_url.format(
                self.app.config["BASE_URL"],
                self.app.config["OAUTH2_ID"],
                self.app.config["OAUTH2_URI"],
            ),
        )

    def test_auth(self, m):
        with self.client.session_transaction() as sess:
            sess["api_key"] = "@cc3$$_t0k3n"

        payload = {"custom_canvas_course_id": "1", "custom_canvas_user_id": "1"}
        refresh_token = "R3fr3$h_t0k3n"
        expiry_date = int(time.time()) + 1800

        m.register_uri("GET", "/api/v1/users/1/profile", status_code=200)

        # pre-create user
        user = lti.Users(1, refresh_token, expiry_date)
        lti.db.session.add(user)
        lti.db.session.commit()

        # Confirm that user is already in DB
        user = lti.Users.query.filter_by(
            user_id=payload["custom_canvas_user_id"]
        ).first()
        self.assertIsInstance(user, lti.Users)

        response = self.client.post(
            self.generate_launch_request(
                url_for("auth"),
                body=payload,
                http_method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            data=payload,
        )

        self.assert_redirects(response, url_for("index"))

    # get_sessionless_url
    def test_get_sessionless_url_is_course_nav_fail(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1
            sess["api_key"] = "@cc3$$_t0k3n"

        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools/sessionless_launch",
            status_code=404,
        )

        response = self.client.get(
            self.generate_launch_request(
                url_for("get_sessionless_url", lti_id=1, is_course_nav=True)
            )
        )

        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Error in a response from Canvas, please refresh and try again.",
            response.data,
        )

    def test_get_sessionless_url_is_course_nav_succeed(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1
            sess["api_key"] = "@cc3$$_t0k3n"

        launch_url = "example.com/launch_url"

        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools/sessionless_launch",
            status_code=200,
            json={"url": launch_url},
        )

        response = self.client.get(
            self.generate_launch_request(
                url_for("get_sessionless_url", lti_id=1, is_course_nav=True)
            )
        )

        self.assert_200(response)
        self.assertEqual(response.data, launch_url.encode("utf-8"))

    def test_get_sessionless_url_not_course_nav_fail(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1
            sess["api_key"] = "@cc3$$_t0k3n"

        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools/sessionless_launch",
            status_code=404,
        )

        response = self.client.get(
            self.generate_launch_request(
                url_for("get_sessionless_url", lti_id=1, is_course_nav=False)
            )
        )

        self.assert_200(response)
        self.assert_template_used("error.html")
        self.assertIn(
            b"Error in a response from Canvas, please refresh and try again.",
            response.data,
        )

    def test_get_sessionless_url_not_course_nav_succeed(self, m):
        with self.client.session_transaction() as sess:
            sess[LTI_SESSION_KEY] = True
            sess["oauth_consumer_key"] = "key"
            sess["roles"] = "Instructor"
            sess["canvas_user_id"] = 1
            sess["course_id"] = 1
            sess["api_key"] = "@cc3$$_t0k3n"

        launch_url = "example.com/launch_url"

        m.register_uri(
            "GET",
            "/api/v1/courses/1/external_tools/sessionless_launch",
            status_code=200,
            json={"url": launch_url},
        )

        response = self.client.get(
            self.generate_launch_request(
                url_for("get_sessionless_url", lti_id=1, is_course_nav=False)
            )
        )

        self.assert_200(response)
        self.assertEqual(response.data, launch_url.encode("utf-8"))


class UtilsTests(unittest.TestCase):
    app = Flask("test")
    app.config["WHITELIST"] = "whitelist.json"
    app.config["BASE_URL"] = "https://example.edu/"

    @classmethod
    def setUpClass(cls):
        app = lti.app
        app.config["BASE_URL"] = "https://example.edu/"
        app.config["WHITELIST"] = "whitelist.json"
        return app

    def test_filter_tool_list_empty_file(self):
        with self.app.app_context():
            with self.assertRaises(JSONDecodeError):
                with patch("builtins.open", mock_open(read_data="")):
                    utils.filter_tool_list(1, "password")

    def test_filter_tool_list_empty_data(self):
        with self.app.app_context():
            with self.assertRaisesRegex(ValueError, r"whitelist\.json is empty"):
                with patch("builtins.open", mock_open(read_data="{}")):
                    utils.filter_tool_list(1, "password")

    @patch("canvasapi.canvas.Canvas.get_course")
    @patch("canvasapi.course.Course.get_external_tools")
    def test_filter_tool_list(self, mock_get_course, mock_get_external_tools):
        # TODO: figure out the best way to mock canvasapi objects to finish testing this method
        pass

    def test_slugify(self):
        self.assertEqual(utils.slugify("test"), "test")
        self.assertEqual(utils.slugify("CAPSTOLOWER"), "capstolower")
        self.assertEqual(utils.slugify("spaces to dashes"), "spaces-to-dashes")
