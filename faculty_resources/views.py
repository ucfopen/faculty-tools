from flask import Flask, render_template, session, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from pycanvas import Canvas
from pycanvas.exceptions import CanvasException
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from logging import Formatter
import requests
import json
import settings

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
db = SQLAlchemy(app)

# ============================================
# Logging
# ============================================


if __name__ == '__main__':
    handler = RotatingFileHandler(
                'errorland.log',
                maxBytes=settings.LOG_MAX_BYTES,
                backupCount=settings.LOG_BACKUP_COUNT
            )
    handler.setLevel(logging.getLevelName(logging.INFO))
    handler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s: %(lineno)d of %(funcName)s]'
    ))
    app.logger.addHandler(handler)


# ============================================
# DB Model
# ============================================


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    refresh_key = db.Column(db.String)
    expires_in = db.Column(db.String)

    def __init__(self, user_id, refresh_key, expires_in):
        self.user_id = user_id
        self.refresh_key = refresh_key
        self.expires_in = expires_in

    def __repr__(self):
        return '<User %r>' % self.user_id

# ============================================
# Utility Functions
# ============================================


def check_valid_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """
        Decorator to check if the user is allowed access to the app.

        If user is allowed, return the decorated function.
        Otherwise, return an error page with corresponding message.
        """

        if request.form:
            session.permanent = True
            # 1 hour long session
            app.permanent_session_lifetime = timedelta(minutes=60)
            session['course_id'] = request.form.get('custom_canvas_course_id')
            session['canvas_user_id'] = request.form.get('custom_canvas_user_id')

            roles = request.form['roles']
            if "Administrator" in roles:
                session['admin'] = True
                session['instructor'] = True
            if "Instructor" in roles:
                session['instructor'] = True

        # no session and no request
        if not session:
            if not request.form:
                app.logger.warning("No session and no request. Not allowed.")
                return render_template(
                    'error.html',
                    msg='Not allowed!'
                )

        # no canvas_user_id
        if not request.form.get('custom_canvas_user_id') and 'canvas_user_id' not in session:
            app.logger.warning("No canvas user ID. Not allowed.")
            return render_template(
                'error.html',
                msg='Not allowed!'
            )

        # no course_id
        if not request.form.get('custom_canvas_course_id') and 'course_id' not in session:
            app.logger.warning("No course ID. Not allowed.")
            return render_template(
                'error.html',
                msg='No course_id provided.'
            )

        # not permitted
        if 'instructor' not in session:
            app.logger.warning("Not enrolled as Teacher or an Admin. Not allowed.")
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher or Designer.'
            )

        # make sure that they are enrolled in this course
        canvas = Canvas(settings.API_URL, settings.API_KEY)
        user = canvas.get_user(session['canvas_user_id'])
        user_enrollments = user.get_enrollments()

        enrolled = False

        for enrollment in user_enrollments:
            if enrollment.course_id == int(session['course_id']):
                if enrollment.type == "TeacherEnrollment":
                    enrolled = True

        if enrolled is False and 'admin' not in session:
            app.logger.warning("Not an Admin. Not allowed.")
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher or Designer.'
            )

        return f(*args, **kwargs)
    return decorated_function

# ============================================
# Web Views / Routes
# ============================================


@app.route("/")
@check_valid_user
def index():
    """
    Main entry point to web application, call all the things and send the data to the template
    """

    # Get data from the higher level account
    # account = canvas.get_account(settings.UCF_ID)
    # 1 for dev

    # Test API key to see if they need to reauthenticate
    auth_header = {'Authorization': 'Bearer ' + session['api_key']}
    r = requests.get(settings.API_URL+'accounts/%s/' % settings.UCF_ID, headers=auth_header)

    if 'WWW-Authenticate' in r.request.headers or r.status_code == 401:
        # reroll oauth
        app.logger.info(
            '''WWW-Authenticate found in headers, or status code was 401.
            Re-rolling oauth.\n {0} \n {1} \n {1}'''.format(r.status_code, r.request.headers, r.url)
        )
        return redirect(settings.BASE_URL+'login/oauth2/auth?client_id='+settings.oauth2_id +
                        '&response_type=code&redirect_uri='+settings.oauth2_uri)

    canvas = Canvas(settings.API_URL, session['api_key'])
    # account = canvas.get_account(settings.UCF_ID)
    account = canvas.get_account(1)
    global_ltis = account.get_external_tools()
    course = canvas.get_course(session['course_id'])
    course_ltis = course.get_external_tools()

    lti_requests = []
    lti_list = []

    for lti in course_ltis:
        lti_requests.append(lti)
    for lti in global_ltis:
        lti_requests.append(lti)

    # load our white list
    json_data = json.loads(open('whitelist.json').read())

    for lti in lti_requests:
        try:
            # check if the LTI is in the whitelist
            for data in json_data:
                if lti.name in data['name']:
                    lti_list.append({
                        "name": lti.name,
                        "id": lti.id,
                        "sessionless_launch_url": lti.get_sessionless_launch_url(),
                        "desc": data['desc'],
                        "heading": data['subheading'],
                        "screenshot": data['screenshot'],
                        "logo": data['logo'],
                        "filter_by": data['filter_by']
                    })

        except CanvasException:
            # this lti threw an exception when talking to Canvas
            app.logger.error(
                "Canvas exception:\n {0} \n LTI: {1} \n LTI List: {2} \n".format(
                    CanvasException, lti, lti_list
                )
            )

            pass

    return render_template(
        "mockup1.html",
        ltis=lti_list,
        course=session['course_id']
    )


@app.route("/xml/", methods=['POST', 'GET'])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    try:
        return render_template('test.xml', url=request.url_root)
    except:
        app.logger.error("\nNo XML file.")

        return render_template('error.html', msg="No XML file")

# OAuth login


@app.route('/oauthlogin', methods=['POST', 'GET'])
# @check_valid_user
def oauth_login():

    code = request.args.get('code')
    payload = {
        'grant_type': 'authorization_code',
        'client_id': settings.oauth2_id,
        'redirect_uri': settings.oauth2_uri,
        'client_secret': settings.oauth2_key,
        'code': code
    }
    r = requests.post(settings.BASE_URL+'login/oauth2/token', data=payload)

    if r.status_code == 500:
        # Canceled oauth or server error
        app.logger.error(
            '''Status code 500 from oauth, authentication error\n
            User ID: {0} Course: {1} \n {2} \n Request headers: {3} \n {4}'''.format(
                session['canvas_user_id'], session['course_id'],
                r.url, r.request.headers, r.json()
            )
        )

        msg = "Authentication error, please refresh and try again."
        return render_template("error.html", msg=msg)

    if 'access_token' in r.json():
        session['api_key'] = r.json()['access_token']

        if 'refresh_token' in r.json():
            session['refresh_token'] = r.json()['refresh_token']

        if 'expires_in' in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = datetime.now()
            expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
            session['expires_in'] = expires_in
        try:

            # add to db
            new_user = Users(
                session['canvas_user_id'],
                session['refresh_token'],
                session['expires_in']
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(
                "Error in adding new user to db: \n {0} {1} {2} {3} ".format(
                    e, session['canvas_user_id'], session['refresh_token'], session['expires_in']
                )
            )
            msg = "Authentication error, please refresh and try again."
            return render_template("error.html", msg=msg)

    app.logger.warning(
        "Some other error\n User: {0} Course: {1} \n {2} \n Request headers: {3} \n {4}".format(
            session['canvas_user_id'], session['course_id'],
            r.url, r.request.headers, r.json()
        )
    )
    msg = "Authentication error, please refresh and try again."
    return render_template("error.html", msg=msg)


@app.route('/auth', methods=['POST', 'GET'])
@check_valid_user
def auth():

    # if they aren't in our DB/their token is expired or invalid
    try:
        user = Users.query.filter_by(user_id=int(session['canvas_user_id'])).first()
        # get or add
        if user is not None:

            expiration_date = datetime.strptime(user.expires_in, '%Y-%m-%d %H:%M:%S.%f')

            refresh_token = user.refresh_key
            if datetime.now() > expiration_date or 'api_key' not in session:
                # expired! Use the refresh token
                app.logger.info(
                    '''Expired refresh token or api_key not in session\n
                    User: {0} \n Expiration date in db: {1}'''.format(user.user_id, user.expires_in)
                )
                payload = {
                    'grant_type': 'refresh_token',
                    'client_id': settings.oauth2_id,
                    'redirect_uri': settings.oauth2_uri,
                    'client_secret': settings.oauth2_key,
                    'refresh_token': refresh_token
                }
                r = requests.post(settings.BASE_URL+'login/oauth2/token', data=payload)
                if 'access_token' in r.json():
                    session['api_key'] = r.json()['access_token']
                    app.logger.info(
                        "New access token created\n User: {0}".format(user.user_id)
                    )

                    if 'refresh_token' in r.json():
                        session['refresh_token'] = r.json()['refresh_token']

                    if 'expires_in' in r.json():
                        # expires in seconds
                        # add the seconds to current time for expiration time
                        current_time = datetime.now()
                        expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
                        session['expires_in'] = expires_in
                    try:
                        user.expires_in = session['expires_in']
                        db.session.commit()
                    except Exception as e:
                        # log error
                        app.logger.error(
                            '''Error in updating user in the db:\n {0} \n user ID {1} \n
                            Refresh token {2} \n Oauth expiration in session {3}'''.format(
                                session['canvas_user_id'],
                                session['refresh_token'],
                                session['expires_in']
                            )
                        )
                        msg = "Authentication error, please refresh and try again."
                        return render_template("error.html", msg=msg)

                    return redirect(url_for('index'))
            else:
                # good to go!
                # test the api key
                auth_header = {'Authorization': 'Bearer ' + session['api_key']}
                r = requests.get(settings.API_URL + 'users/%s/profile' %
                                 (session['canvas_user_id']), headers=auth_header)
                # check for WWW-Authenticate
                # https://canvas.instructure.com/doc/api/file.oauth.html
                if 'WWW-Authenticate' not in r.request.headers and r.status_code != 401:
                    return redirect(url_for('index'))
                else:
                    app.logger.info(
                        '''Reauthenticating: \n User ID: {0} \n Course: {1}
                        Refresh token: {2} \n
                        Oauth expiration in session: {3} \n {4} \n {5} \n {6}'''.format(
                            session['canvas_user_id'], session['course_id'],
                            session['refresh_token'], session['expires_in'],
                            r.status_code, r.url, r.request.headers
                        )
                    )
                    return redirect(
                        settings.BASE_URL+'login/oauth2/auth?client_id=' +
                        settings.oauth2_id + '&response_type=code&redirect_uri=' +
                        settings.oauth2_uri
                    )
                app.logger.error(
                    '''Some other error: \n
                    User ID: {0}  Course: {1} \n Refresh token: {2} \n
                    Oauth expiration in session: {3} \n {4} \n {5} \n {6} {7}'''.format(
                        session['canvas_user_id'], session['course_id'],
                        session['refresh_token'], session['expires_in'], r.status_code,
                        r.url, r.request.headers, r.json()
                    )
                )
                msg = "Authentication error, please refresh and try again."
                return render_template("error.html", msg=msg)
        else:
            # not in db, go go oauth!!
            app.logger.info(
                "Person doesn't have an entry in db, redirecting to oauth: {0}".format(
                    session['canvas_user_id']
                )
            )
            return redirect(settings.BASE_URL+'login/oauth2/auth?client_id='+settings.oauth2_id +
                            '&response_type=code&redirect_uri='+settings.oauth2_uri)
    except Exception as e:
        # they aren't in the db, so send em to the oauth stuff
        app.logger.info(
            "Error getting a person from the db, reuathenticating: {0} {1}".format(
                session['canvas_user_id'], e
            )
        )
        return redirect(settings.BASE_URL+'login/oauth2/auth?client_id='+settings.oauth2_id +
                        '&response_type=code&redirect_uri='+settings.oauth2_uri)
    app.logger.warning(
        "Some other error, {0} {1}".format(
            session['canvas_user_id'],
            session['course_id']
        )
    )
    msg = "Authentication error, please refresh and try again."
    return render_template("error.html", msg=msg)


# ============================================
# LTI Setup & Config
# ============================================

if __name__ == "__main__":
    app.debug = True
    app.secret_key = settings.secret_key
    app.run(host="0.0.0.0", port=settings.port)
